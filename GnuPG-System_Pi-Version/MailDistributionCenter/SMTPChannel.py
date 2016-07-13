'''
Created on 13.06.2016

@author: Fabian Reiber
@version: 1.0
This module describes the main SMTP Channel. The module takes the messages and check what
to do with them. It also sends messages to the recipients, or in error cases to the sender.
'''

from email.parser import HeaderParser
from email.parser import Parser
from email.utils import getaddresses
from email.utils import parseaddr
from smtpd import SMTPServer

from DistributerKeyManagement import DistributerKeyManager
from DistributerKeyManagementException.KeyDeleteException import KeyDeleteException
from DistributerKeyManagementException.NoAddedKeyException import NoAddedKeyException
from DistributerKeyManagementException.NoKeyException import NoKeyException
from DistributerManagement import DistributerManager
from DistributerManagementException.DBConnectionException import DBConnectionException
from DistributerManagementException.InvalidDistributerAddressException import InvalidDistributerAddressException
from DistributerManagementException.NoFingerprintException import NoFingerprintException
from DistributerManagementException.NoUserException import NoUserException
from GnuPGManagementCenter import GnuPGManager
from GnuPGManagementCenterException.ExtractFingerprintException import ExtractFingerprintException
from GnuPGManagementCenterException.NoDistributerKeyIDsException import NoDistributerKeyIDsException
from GnuPGManagementCenterException.NoDistributerKeysException import NoDistributerKeysException
from GnuPGManagementCenterException.ReEncryptionException import ReEncryptionException
from GnuPGManagementCenterException.VerifyException import VerifyException
from MailDistributionCenter import SubjectCommand
from MailDistributionCenter.MTASendThread import MTASendThread
from MailDistributionCenterException.CheckSignatureException import CheckSignatureException
from MailDistributionCenterException.ParseHeaderException import ParseHeaderException
from util import _util
from util.GnuPGSystemLogger import GnuPGSystemLogger
from utilException.InvalidKeyException import InvalidKeyException
from utilException.NoEncryptionPartException import NoEncryptionPartException
from utilException.NoSignedPartException import NoSignedPartException


class SMTPChannel(SMTPServer):

    def __init__(self, param, remote):
        SMTPServer.__init__(self, localaddr=param, remoteaddr=remote)
        self.dm = DistributerManager.DistributerManager()
        self.dkm = DistributerKeyManager.DistributerKeyManager()
        self.gnupg = GnuPGManager.GnuPGManager()
        self.fromAddr = ''
        self.toAddr = list()
        self.subject = ''
        self.message = None
        self.type = ''
        self.threadList = list()
        """
            Logging only for server-side errors to trace problems. 
        """
        self.__logger = GnuPGSystemLogger('smtpChannel')
   
    def get_from_addr(self):
        return self.__fromAddr
    
    def get_to_addr(self):
        return self.__toAddr

    def get_subject(self):
        return self.__subject
    
    def get_message(self):
        return self.__message
    
    def get_type(self):
        return self.__type

    def get_thread_list(self):
        return self.__threadList

    def set_from_addr(self, value):
        self.__fromAddr = value
    
    def set_to_addr(self, value):
        self.__toAddr = value
    
    def append_to_addr(self, value):
        self.__toAddr = self.__toAddr + [value]
    
    def set_subject(self, value):
        self.__subject = value   
    
    def set_message(self, value):
        self.__message = value
        
    def set_type(self, value):
        self.__type = value
    
    def set_thread_list(self, value):
        self.__threadList = value
        
    def append_thread_list(self, value):
        self.__threadList = self.__threadList + [value]
        
    def process_message(self, peer, mailfrom, rcpttos, data):
        """
            The messages was given from the SMTP server to this method. First of all it parse
            the header of the mail, to get more infrmations. Then it need to analyze the subject
            to choose the right method.
            @param peer: Informations about the peer which send the mail.
            @param mailfrom: The sender mail address.
            @param rcpttos: The recipient mail addresses.
            @param data: The mail as a string.
        """
        
        try:
            self.__parseHeader(data)
            subject = self.get_subject().split(' ')
            msg = Parser().parsestr(data)
            self.set_message(msg)
            if len(subject) == 1:
                if subject[0] == SubjectCommand.SubjectCommand.ADDTODIST.__str__():
                    self.set_type(SubjectCommand.SubjectCommand.ADDTODIST.__str__())
                    self.__addToDist()
                elif subject[0] == SubjectCommand.SubjectCommand.CHANGEPK.__str__():
                    self.set_type(SubjectCommand.SubjectCommand.CHANGEPK.__str__())
                    self.__changePk()
                elif subject[0] == SubjectCommand.SubjectCommand.DELFROMDIST.__str__():
                    self.set_type(SubjectCommand.SubjectCommand.DELFROMDIST.__str__())
                    self.__delFromDist()
                elif subject[0] == SubjectCommand.SubjectCommand.GETPK.__str__():
                    self.set_type(SubjectCommand.SubjectCommand.GETPK.__str__())
                    self.__getPk()
                else:
                    self.set_type(SubjectCommand.SubjectCommand.REENCRYPT.__str__())
                    self.__reEncryptMail()
            else:
                self.set_type(SubjectCommand.SubjectCommand.REENCRYPT.__str__())
                self.__reEncryptMail()
        except ParseHeaderException as e:
            self.__logger.logError(e.__str__())  
            
    def close(self):
        """
            Overrides the close-method of asyncore. When it will be called it is necessary to wait
            for the MTASendThreads to finish.
        """
        SMTPServer.close(self)
        if len(self.get_thread_list()) > 0:
            print('there are some MTASendThreads running...\nyou need to wait until they are finished')
            for thread in self.get_thread_list():
                thread.join()      
            
    def __addToDist(self):
        """
            Add the sender of the mail to the distributer in the recipient field of the header.
            It is necessary that the mail is signed with the sender key. The public-key from 
            the sender needs to be in the attachment. At the end the sender will receive a mail
            with the status of the process. Was it successful the public-keys of the server are
            attached.
        """
        addrFingerprintKeyInfSender = {}
        toAddr = self.get_to_addr()
        for distAddr in toAddr:
            try:
                self.dm.isSenderOnDist(self.get_from_addr(), distAddr)
            except NoUserException:
                #If the mail address is not on the distributer, we need to add it.
                try: 
                    (mailType, sigDict) = _util.getMIMEPartsSig(self.get_message())
                    userKey = _util.extractKey(sigDict.keys())
                    fingerprint = self.gnupg.extractFingerprint(userKey)
                    addrFingerprintKeyInfSender[self.get_from_addr()] = (fingerprint, userKey)
                    self.gnupg.verifySenderSig(mailType, sigDict, userKey, fingerprint)
                    self.dm.addNewAddr(self.get_from_addr(), distAddr, fingerprint)
                    self.dkm.addNewKey(userKey)
                    (keyIDEnc, keyIDSig) = self.gnupg.getKeyIDsFromDist(distAddr)
                    distKeys = self.gnupg.getKeysFromDist(keyIDEnc, keyIDSig)
                    self.__callMTAThread(distAddr, 'ADDED SUCCESSFUL TO DISTRIBUTER ' + distAddr 
                                         + '\nSERVER-KEYS ARE IN THE ATTACHMENT', addrFingerprintKeyInfSender, distKeyIDSig=keyIDSig, distKeys=distKeys)
                except NoSignedPartException as e:
                    self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
                except InvalidKeyException as e:
                    self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
                except ExtractFingerprintException as e:
                    self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
                except VerifyException as e:
                    self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
                except (DBConnectionException, InvalidDistributerAddressException, NoFingerprintException) as e:
                    self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
                except (NoAddedKeyException, NoDistributerKeyIDsException, NoDistributerKeysException) as e:
                    """
                        Undoing add-operations: If there occurred an exception in adding the new address
                        or the new key, the add-operation(s) need(s) to undo:
                        1. case: new key could not be added. It's not a problem to delete a key which isn't there.
                        But the new address needs to delete.
                        2. case: there are no distributer key-ids or keys. The new address and key needs to be deleted.
                    """
                    exceptionMsg = e.__str__()
                    try:
                        self.dm.delAddrFromDist(self.get_from_addr(), distAddr)
                        self.dkm.delKeyFromServer(fingerprint)
                    except (DBConnectionException, KeyDeleteException) as ee:
                        exceptionMsg += ' AND WHILE UNDOING ADD-OPERATION, ANOTHER EXCEPTION OCCURRED: ' + ee.__str__()
                    self.__callMTAThread(distAddr, exceptionMsg, addrFingerprintKeyInfSender)        

    def __callMTAThread(self, distAddr, userInfo, addrFingerprintKeyInf, distKeyIDSig=None, distKeys=None, addrMsgDict={}):
        """
            Starts an MTASendThread-Instance as a thread.
        """
        thread = MTASendThread(distAddr, self.get_from_addr(), userInfo, addrFingerprintKeyInf, distKeyIDSig, distKeys, addrMsgDict)
        thread.start()
        self.append_thread_list(thread)

    def __changePk(self):
        """
            Change the public-key of the sender which is corresponding with the recipient 
            distributer mail-address. It also change the fingerprint in the database.
            It is necessary that the mail is signed with the new key-pair. Also the new
            key need to be in the attachment. At the end the sender will receive a mail
            with the status of the process. 
        """
        addrFingerprintKeyInfSender = {}
        toAddr = self.get_to_addr()
        for distAddr in toAddr:
            try:
                (mailType, sigDict) = _util.getMIMEPartsSig(self.get_message())
                newKey = _util.extractKey(sigDict.keys())
                fingerprintOld = self.dm.getFingerprint(self.get_from_addr(), distAddr)
                fingerprintNew = self.gnupg.extractFingerprint(newKey)
                addrFingerprintKeyInfSender[self.get_from_addr()] = (fingerprintNew, newKey)
                self.gnupg.verifySenderSig(mailType, sigDict, newKey, fingerprintNew)
                self.dkm.changeKeyOnServer(fingerprintOld, newKey)
                self.dm.changeFingerprint(self.get_from_addr(), distAddr, fingerprintNew)
                self.__callMTAThread(distAddr, 'CHANGED KEY ON ' + distAddr, addrFingerprintKeyInfSender)
            except DBConnectionException as e:
                self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
            except NoSignedPartException as e:
                self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
            except InvalidKeyException as e:
                self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
            except (NoFingerprintException, InvalidDistributerAddressException) as e:
                self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
            except ExtractFingerprintException as e:
                self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
            except VerifyException as e:
                self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
            except (KeyDeleteException, NoKeyException, NoAddedKeyException) as e:
                self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
                
    def __checkSignature(self, distAddr, addrFingerprintKeyInfSender):
        """
            Checks the signature of the mail.
            @param distAddr: Distributer address on which the sender is registered.
            @param addrFingerprintKeyInfSender: An empty dictionary. After this method it should be filled
            with address as keys and a 2-tuple of fingerprint and keys as values of the recipient (call by reference).
        """
        try:
            (mailType, sigDict) = _util.getMIMEPartsSig(self.get_message())
            fingerprint = self.dm.getFingerprint(self.get_from_addr(), distAddr)
            userKey = self.dkm.getKeyFromUser(fingerprint)
            addrFingerprintKeyInfSender[self.get_from_addr()] = (fingerprint, userKey)
            self.gnupg.verifySenderSig(mailType, sigDict, userKey, fingerprint)
        except NoSignedPartException as e:
            raise CheckSignatureException(e.__str__())
        except (DBConnectionException, NoFingerprintException, InvalidDistributerAddressException) as e:
            raise CheckSignatureException(e.__str__())
        except NoKeyException as e:
            raise CheckSignatureException(e.__str__())
        except VerifyException as e:
            raise CheckSignatureException(e.__str__())

    def __delFromDist(self):
        """
            The sender will be deleted from the distributer in the recipient field of the header.
            It is necessary that the mail is signed with the sender key. At the end the sender will
            receive a mail with the status of the process. 
        """
        addrFingerprintKeyInfSender = {}
        toAddr = self.get_to_addr()
        for distAddr in toAddr:
            try:
                self.__checkSignature(distAddr, addrFingerprintKeyInfSender)
                deleted = self.dm.delAddrFromDist(self.get_from_addr(), distAddr)
                if deleted:
                    (fingerprint, _userkey) = addrFingerprintKeyInfSender[self.get_from_addr()]
                    self.dkm.delKeyFromServer(fingerprint)
                self.__callMTAThread(distAddr, 'SUCCESSFUL DELETED FROM DISTRIBUTER ' + distAddr, addrFingerprintKeyInfSender)
            except CheckSignatureException as e:
                self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
            except DBConnectionException as e:
                self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
            except KeyDeleteException as e:
                self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)

    def __getPk(self):
        """
            The sender get the public-keys from the distributer in the recipient field of the header.
            It is necessary that the mail is signed with the sender key. At the end the sender will
            receive a mail with the status of the process. Was it successful the public-keys of the 
            server are attached.
        """
        addrFingerprintKeyInfSender = {}
        toAddr = self.get_to_addr()
        for distAddr in toAddr:
            try:
                self.__checkSignature(distAddr, addrFingerprintKeyInfSender)
                (keyIDEnc, keyIDSig) = self.gnupg.getKeyIDsFromDist(distAddr)
                distKeys = self.gnupg.getKeysFromDist(keyIDEnc, keyIDSig)
                self.__callMTAThread(distAddr, 'KEYS FROM DISTRIBUTER ' + distAddr, addrFingerprintKeyInfSender, distKeyIDSig=keyIDSig, distKeys=distKeys)
            except CheckSignatureException as e:
                self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
            except DBConnectionException as e:
                self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
            except NoDistributerKeyIDsException as e:
                self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
            except NoDistributerKeysException as e:
                self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender, distKeyIDSig=keyIDSig)

    def __parseHeader(self, data):
        """
            Parse the Header of the message and store the values.
            @param data: The message as a string.
            @raise ParseHeaderException: If the header could not be parsed.
        """
        header = HeaderParser().parsestr(data)
        self.set_to_addr([])
        try:
            tos = header.get_all('to', [])
            ccs = header.get_all('cc', [])
            resent_tos = header.get_all('resent-to', [])
            resent_ccs = header.get_all('resent-cc', [])
            all_recipients = getaddresses(tos + ccs + resent_tos + resent_ccs)
            
            for addr in all_recipients:
                if (addr[1] != '') and ('@' in addr[1]):
                    self.append_to_addr(addr[1])
                
            self.set_from_addr(parseaddr(header['From'])[1])
            self.set_subject(header['Subject'])
        except:
            raise ParseHeaderException('COULD NOT PARSE HEADER')

    def __reEncryptMail(self):
        """
            The message will be re-encrypt by the system. First the sender needs to be on the distributer.
            Then it is necessary to know which mail-address are on the server. After it the encrypted message
            from the sender will be re-encrypt. If there is something wrong, the sender will receive 
            a mail with the status.
        """
        addrFingerprintKeyInfRecipients = {}
        addrFingerprintKeyInfSender = {}
        toAddr = self.get_to_addr()
        for distAddr in toAddr:
            try:
                self.dm.isSenderOnDist(self.get_from_addr(), distAddr)
                senderFingerprint = self.dm.getFingerprint(self.get_from_addr(), distAddr)
                senderKey = self.dkm.getKeyFromUser(senderFingerprint)
                addrFingerprintKeyInfSender[self.get_from_addr()] = (senderFingerprint, senderKey)
                addrFingerprintList = self.dm.getAllAddressesWithFingerprint(distAddr, self.get_from_addr())
                addrFingerprintKeyInfRecipients = self.dkm.getKeyInfFromUsers(addrFingerprintList)
                encryptedParts = _util.getMIMEPartEnc(self.get_message())
                (distKeyIDEnc, distKeyIDSig) = self.gnupg.getKeyIDsFromDist(distAddr)
                reEncResult = self.gnupg.reEncrypt(addrFingerprintKeyInfRecipients, self.get_from_addr(), senderKey, senderFingerprint, encryptedParts, distAddr, self.get_subject(), distKeyIDEnc, distKeyIDSig)
                self.__callMTAThread(distAddr, '', addrFingerprintKeyInfRecipients, distKeyIDSig=distKeyIDSig, addrMsgDict=reEncResult)
            except DBConnectionException as e:
                self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
            except NoUserException as e:
                self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
            except (NoFingerprintException, InvalidDistributerAddressException) as e:
                self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
            except NoKeyException as e:
                self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
            except NoEncryptionPartException as e:
                self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
            except NoDistributerKeyIDsException as e:
                self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender)
            except ReEncryptionException as e:
                self.__callMTAThread(distAddr, e.__str__(), addrFingerprintKeyInfSender, distKeyIDSig=distKeyIDSig)
      
    fromAddr = property(get_from_addr, set_from_addr, None, None)
    toAddr = property(get_to_addr, set_to_addr, None, None)
    subject = property(get_subject, set_subject, None, None)
    toAddr = property(get_to_addr, set_to_addr, None)
    message = property(get_message, set_message, None, None)
    type = property(get_type, set_type, None, None)
    threadList = property(get_thread_list, set_thread_list, None, None)
    