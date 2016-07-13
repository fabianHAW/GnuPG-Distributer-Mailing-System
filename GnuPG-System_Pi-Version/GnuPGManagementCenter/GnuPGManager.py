'''
Created on 13.06.2016

@author: Fabian Reiber
@version: 1.0
This module is responsible for the re-encryption.
'''

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.parser import Parser
import gc
import gnupg
import mimetypes
import os

from GnuPGManagementCenter import MSGStatus
from GnuPGManagementCenterException.ExtractFingerprintException import ExtractFingerprintException
from GnuPGManagementCenterException.NoDistributerKeyIDsException import NoDistributerKeyIDsException
from GnuPGManagementCenterException.NoDistributerKeysException import NoDistributerKeysException
from GnuPGManagementCenterException.ReEncryptionException import ReEncryptionException
from GnuPGManagementCenterException.SigningException import SigningException
from GnuPGManagementCenterException.VerifyException import VerifyException
from util import _util
from util.GnuPGSystemLogger import GnuPGSystemLogger
from utilException.NoSignedPartException import NoSignedPartException


class GnuPGManager:
    
    __BIN = '/usr/bin/gpg'
    __HOME = '/home/pi/.gnupgDist'
    __HOME_TMP = '/tmp/.gnupg'
    
    def __init__(self, homeTmp=None):
        self.gpg = gnupg.GPG(binary=GnuPGManager.__BIN, homedir=GnuPGManager.__HOME)
        if homeTmp is not None:
            self.gpgTmp = gnupg.GPG(binary=GnuPGManager.__BIN, homedir=homeTmp)
        else:
            self.gpgTmp = gnupg.GPG(binary=GnuPGManager.__BIN, homedir=GnuPGManager.__HOME_TMP)
        
        """
            Logging only for server-side errors to trace problems. 
        """
        self.__logger = GnuPGSystemLogger('gnupgManager')
      
    def extractFingerprint(self, key):
        """
            Extern-Helper-Method: Imports temporarily a given key to extract the fingerprint.
            After it, the key will be deleted.
            @param key: The key to import temporarily.
            @raise ExtractFingerprintException: If the key is invalid, it could not be import.
            @return: The extracted fingerprint.
        """
        try:
            self.gpgTmp.import_keys(key)
            fingerprint = self.gpgTmp.list_keys(secret=False)[0]['fingerprint']
            self.gpgTmp.delete_keys(fingerprint, secret=False, subkeys=False)
            return fingerprint
        except Exception as e:
            raise ExtractFingerprintException('IMPORTING OR EXTRACTING FINGERPRINT FAILD: ' + e.__str__())
            
    def getKeysFromDist(self, keyIDEnc, keyIDSig):
        """
            Exports the public-keys for the given key-ids.
            @param keyIDEnc: Key-id for the public-key to encrypt messages.
            @param keyIDSig: Key-id for the public-key to sign messages.
            @raise NoDistributerKeysException: If there are no keys found.
            @return: The keys in one object.
        """
        keys = self.gpg.export_keys([keyIDEnc, keyIDSig], secret=False, subkeys=False)
        if keys == '':
            raise NoDistributerKeysException('NO DISTRIBUTER KEYS FOUND') 
        return keys
    
    def getKeyIDsFromDist(self, distAddr):
        """
            Extract the two public-key-ids for encryption and signing of a given distributer address.
            @param distAddr: Given distributer address 
            @raise NoDistributerKeyIDsException: There are no key-ids founded.
            @return: If the key-ids found, they will return as a 2-tuple: (encrypt, sign)
        """
                
        keyIDEnc = None
        keyIDSig = None
        keyList = self.gpg.list_keys(secret=False)
        
        for key in keyList:
            for uid in key['uids']:
                if (distAddr in uid) and ('enc' in uid):
                    keyIDEnc = key['keyid']
                    break
                elif (distAddr in uid) and ('sig' in uid):
                    keyIDSig = key['keyid']
                    break
                
        if _util.objectsNotNone(keyIDEnc, keyIDSig):
            return (keyIDEnc, keyIDSig)
        else: 
            raise NoDistributerKeyIDsException('NO DISTRIBUTER KEY-IDS FOUND')
    
    def reEncrypt(self, addrFingerprintKeyInf, senderAddr, senderKey, senderFingerprint, encryptedParts, distAddr, subject, distKeyIDEnc, distKeyIDSig): 
        """
            The given message will be decrypted and the signature will be verified. At the end
            it needs to create a new sigend and encrypted message for every recipient. 
            The mail could be in PGP/MIME or Inline-PGP format. It needs to be differ in this method.
            @param addrFingerprintKeyInf: It stores the informations about any recipient:
            (recipientAddr, (recipientFingerprint, recipientKey))
            @param senderAddr: Mail Address of the sender.
            @param senderKey: Key of the sender to verify the signature, which need to import temporarily.
            @param senderFingerprint: Fingerprint of the sender to delete the key.
            @param encryptedParts: A 2-tuple: 1. element: partType := if the message is in PGP/MIME or Inline-PGP
            2. element: msgList := a list with encrypted message(s).
            @param distAddr: Distributer address on which the mail arrived.
            @param subject: Subject of the mail.
            @param distKeyIDEnc: Key-ID for encryption of the distributer. 
            @param distKeyIDSig: Distributer Key-Id to sign the new mail.
            @raise ReEncryptionException: If it was not possible to re-encrypt the mail. A specific 
            message is passed.
            @return: An address-message dictionary: {mail-address : encrypted mail}
        """

        addressMsgDict = {}
        (partType , msgList) = encryptedParts
        multiMime = MIMEMultipart()
        counter = 0
        try:
            for part in msgList:
                partTmp = part
                if (partType == 'inline') and (part.get_content_type() != 'multipart/mixed'):
                    if part.get_content_type() == 'text/plain':
                        part = part.get_payload(decode=True)
                        msgDecParsed = self.__decryptAndVerifyMsg(part, distKeyIDEnc, senderKey, senderFingerprint)
                       
                        partTmp.set_payload(msgDecParsed.get_payload(decode=True))
                        multiMime.attach(partTmp)
                    else:
                        filename = self.__getFilename(part, counter)
                        part = self.__decryptAndVerifyInlineAttachment(part, distKeyIDEnc, filename, senderKey, senderFingerprint)
                        attachment = _util.generateMIMEAttachmentPart(part, partTmp, filename)
                        counter += 1
                        multiMime.attach(attachment)    
                elif partType == 'mime':
                    msgDecParsed = self.__decryptAndVerifyMsg(part, distKeyIDEnc, senderKey, senderFingerprint)
                    addressMsgDict = self.signAndEncrypt(addrFingerprintKeyInf, senderAddr, msgDecParsed, distAddr, subject, distKeyIDSig)
                    return addressMsgDict
            if msgList:
                addressMsgDict = self.signAndEncrypt(addrFingerprintKeyInf, senderAddr, multiMime, distAddr, subject, distKeyIDSig)
                return addressMsgDict
        except ReEncryptionException as e:
            raise e
        finally:        
            gc.collect()
            
    def signAndEncrypt(self, addrFingerprintKeyInf, senderAddr, msg, distAddr, subject, distKeyIDSig):
        """
            Iterates over the user informations and sign and encrypt every message separately.
            @param addrFingerprintKeyInf: User informations: (recipientAddr, (recipientFingerprint, recipientKey))
            @param msg: The message to sign and encrypt.
            @param distAddr: Distributer address on which the mail arrived.
            @param subject: Subject of the mail.
            @param distKeyIDSig: Distributer Key-Id to sign the new mail.
        """
        addressMsgDict = {}
        msg.attach(MIMEText('This message was send from ' + senderAddr))
        signature = self.gpg.sign(msg.as_string().replace('\n', '\r\n'), default_key=distKeyIDSig, detach=True, clearsign=False)
        msgSigMIME = _util.generateMIMEMsg('signed', msg, signature, None, None, None)
        for item in addrFingerprintKeyInf.items():
            (recipientAddr, (recipientFingerprint, recipientKey)) = item
            self.gpgTmp.import_keys(recipientKey)
            msgEnc = self.gpgTmp.encrypt(msgSigMIME.as_string().replace('\n', '\r\n'), recipientFingerprint)
            self.gpgTmp.delete_keys(recipientFingerprint, secret=False, subkeys=False)
            msgEncMIME = _util.generateMIMEMsg('encrypted', msgEnc, None, distAddr, recipientAddr, subject)
            addressMsgDict[recipientAddr] = msgEncMIME
        
        return addressMsgDict
       
    def signMsg(self, msg, distKeyID):
        """
            Signed a given message with a key which is corresponding to the given key-id.
            @param msg: Message to sign.
            @param distKeyID: Key-id which corresponds to a distributer key-pair.
            @raise SigningException: If the message could not be signed.
        """
        sig = self.gpg.sign(msg.as_string().replace('\n', '\r\n'), default_key=distKeyID, detach=True, clearsign=False)
        if sig.status != MSGStatus.MSGStatus.SIG_OK.__str__():
            raise SigningException('COULD NOT SIGN MESSAGE')
        return sig
    
    def verifySenderSig(self, mailType, sigDict, senderKey, senderFingerprint):
        """
            Verify a message with a given signature. It imports the senderkey temporarily
            and delete it at the end with the fingerprint. The signature also need to be stored in a file.
            @param mailType: Type of the mail: inline for Inline-PGP and mime for PGP/MIME.
            @param sigDict: A message-dictionary: key := message to verify; value := signature of the key.
            @param senderKey: Senderkey to verify the signature.
            @param senderFingerprint: Corresponding fingerprint to the senderkey.
            @raise VerifyException: If the signature could not be verified.
            @raise IOError: If the file could not be read.
        """
        self.gpgTmp.import_keys(senderKey)
        
        if mailType == 'mime':
            try: 
                for sigMsg, signature in sigDict.items():
                    with open('signature.sig', 'wb') as sigFile:
                        sigFile.write(signature)
                    ver = self.gpgTmp.verify_file(sigMsg.as_string().replace('\n', '\r\n'), 'signature.sig')
                    if ver.status != MSGStatus.MSGStatus.VER_OK.__str__():
                        raise VerifyException('SIGNATURE INVALID')
                    os.remove('signature.sig')
            except IOError as e:
                self.__logger.logError(e.__str__())
                raise e
            finally:
                self.gpgTmp.delete_keys(senderFingerprint, secret=False, subkeys=False)
        else:
            try:
                for sigMsg, signature in sigDict.items():
                    if signature is None:
                        ver = self.gpgTmp.verify(sigMsg.get_payload(decode=True))
                        if ver.status != MSGStatus.MSGStatus.VER_OK.__str__():
                            raise VerifyException('SIGNATURE INVALID')
                    else:
                        with open('signature.sig', 'wb') as sigFile:
                            sigFile.write(signature.get_payload(decode=True))
                        with open('text.txt', 'wb') as sigFile:
                            sigFile.write(sigMsg.get_payload(decode=True))
                            
                        with open('text.txt', 'rb') as file:
                            ver = self.gpgTmp.verify_file(file, 'signature.sig')
                            if ver.status != MSGStatus.MSGStatus.VER_OK.__str__():
                                raise VerifyException('SIGNATURE INVALID')
                        os.remove('signature.sig')
                        os.remove('text.txt')
            except IOError as e:
                self.__logger.logError(e.__str__())
                raise e
            finally:
                self.gpgTmp.delete_keys(senderFingerprint, secret=False, subkeys=False)        
    
    def __decryptAndVerifyMsg(self, msg, distKeyIDEnc, senderKey, senderFingerprint):
        """
            Helper-Method: Decrypt and verify a given message.
            @param msg: The given message.
            @param distKeyIDEnc: Key-ID for encryption of the distributer. 
            @param senderKey: Senderkey to import the key and then check the signature of the message.
            @param senderFingerprint: SenderFingerprint to delete the imported senderKey.
            @raise ReEncryptionException: If the decryption or verification failed.
            @return: The decrypted message.
        """
        
        #Need to import the senderkey, so that gpg can verify the message directly.
        self.gpg.import_keys(senderKey)
        msgDec = self.gpg.decrypt(msg)
        self.gpg.delete_keys(senderFingerprint, secret=False, subkeys=False)

        _firstID, secondID = distKeyIDEnc[:len(distKeyIDEnc)//2], distKeyIDEnc[len(distKeyIDEnc)//2:]
        if msgDec.status == MSGStatus.MSGStatus.DEC_OK.__str__():
            if secondID in msgDec.stderr:
                if msgDec.valid:
                    msgDecParsed = Parser().parsestr(msgDec.data.decode('UTF-8'))
                    return msgDecParsed
                else:
                    try:
                        msgDecParsed = Parser().parsestr(msgDec.data.decode('UTF-8'))
                        (mailType, sigDict) = _util.getMIMEPartsSig(msgDecParsed)
                        self.verifySenderSig(mailType, sigDict, senderKey, senderFingerprint)
                        return msgDecParsed
                    except NoSignedPartException as e:
                        raise ReEncryptionException(e.__str__())
                    except VerifyException as e:
                        raise ReEncryptionException(e.__str__())
                    except IOError as e:
                        raise ReEncryptionException('AN IOERROR OCCURRED')
                    finally:
                        self.gpg.delete_keys(senderFingerprint, secret=False, subkeys=False)
            else:
                raise ReEncryptionException('YOU CHOSE THE WRONG PUBLIC KEY TO ENCRYPT THE MESSAGE')
        else:
            raise ReEncryptionException(MSGStatus.MSGStatus.DEC_NOT_OK.__str__())
    
    
    def __decryptAndVerifyInlineAttachment(self, part, distKeyIDEnc, filename, senderKey, senderFingerprint):
        """
            Decrypt an inline attachment with a subprocess call. The gnupg-library can't decrypt it.
            @param part: The attachment in MIME format to decrypt.
            @param distKeyIDEnc: Key-ID for encryption of the distributer. 
            @param filename: The filename of the attachment.
            @param senderKey: Senderkey to import the key and then check the signature of the message.
            @param senderFingerprint: SenderFingerprint to delete the imported senderKey.
            @raise ReEncryptionException: If the decryption or verification failed.
            @return: The decrypted attachment.
        """

        try:
            with open(filename, 'wb') as file:
                file.write(part.get_payload(decode=True))
                
            self.gpg.import_keys(senderKey)
            msgDec = self.gpg.decrypt_file(filename)
            os.remove(filename)
            
            _firstID, secondID = distKeyIDEnc[:len(distKeyIDEnc)//2], distKeyIDEnc[len(distKeyIDEnc)//2:]
            if msgDec.status == MSGStatus.MSGStatus.DEC_OK.__str__():
                if secondID in msgDec.stderr:
                    if msgDec.valid:
                        return msgDec.data
                    else:
                        raise ReEncryptionException('SIGNATURE INVALID')
                else:
                    raise ReEncryptionException('YOU CHOSE THE WRONG PUBLIC KEY TO ENCRYPT THE MESSAGE')
            else:
                raise ReEncryptionException(MSGStatus.MSGStatus.DEC_NOT_OK.__str__())
        except IOError as e:
            self.__logger.logError(e.__str__())
            raise e
        finally:
            self.gpg.delete_keys(senderFingerprint, secret=False, subkeys=False)
    
    def __getFilename(self, part, counter):
        """
            Helper-Method: Determine the filename of the attachment.
            @param part: The attachment in MIME format.
            @param counter: Count the number of attachments.
            @return: The filename of the attachment.
        """
        filename = part.get_filename()
        if not filename:
            ext = mimetypes.guess_extension(part.get_content_type())
            if not ext:
                ext = '.bin'
            filename = 'part-%03d%s' % (counter, ext)
        return filename
     
