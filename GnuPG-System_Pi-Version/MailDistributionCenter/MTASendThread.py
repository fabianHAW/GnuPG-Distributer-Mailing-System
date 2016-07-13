'''
Created on 13.06.2016

@author: Fabian Reiber
@version: 1.0
The MTASendThread will send the prepared re-encrypted mails to the recipient. If the origin mail was not
a re-encrypted mail, the thread needs to prepare the specific mail. It could be the correct mail or a
failure mail with the specific failure status. If it was not possible to send for the first time,
the thread waits and try it again after 1 hour. If it will fail again it will wait 2 hours until 3 days passed.
In that case it sends an error mail to the origin sender with the same send-process. 
'''
import datetime
from smtplib import SMTPSenderRefused, SMTPRecipientsRefused, SMTPDataError
import smtplib
import socket
import threading
import time

from DistributerKeyManagement import DistributerKeyManager
from DistributerKeyManagementException.NoKeyException import NoKeyException
from DistributerManagement import DistributerManager
from DistributerManagementException.DBConnectionException import DBConnectionException
from DistributerManagementException.InvalidDistributerAddressException import InvalidDistributerAddressException
from DistributerManagementException.NoFingerprintException import NoFingerprintException
from GnuPGManagementCenter import GnuPGManager
from GnuPGManagementCenterException.NoDistributerKeyIDsException import NoDistributerKeyIDsException
from GnuPGManagementCenterException.SigningException import SigningException
from util import _util
from util.GnuPGSystemLogger import GnuPGSystemLogger
from utilException.NoMXRecordException import NoMXRecordException


class MTASendThread(threading.Thread):
     
    __RETRY_FIRST_TIME = 3600 #1 hour
    __RETRY_ELSE_TIME = 7200 # 2 hours
    __SENDER_MSG_TIME = 259200 #3 days
    
    """
        Need to lock the access to the signAndEncrypt method of GnuPGManager, because there
        are read/write operations. If there are more then one MTASendThreads, it is possible,
        that they get into a predicament.
    """
    __SIGN_AND_ENCRYPTLOCK = threading.Lock()
    
    def __init__(self, distAddr, senderAddr, userInfo, addrFingerprintKeyInf, distKeyIDSig, distKeys, addrMsgDict, 
                 group=None, target=None, name=None, args=(), kwargs=None, *, daemon=None):
        threading.Thread.__init__(self, group=group, target=target, name=name, args=args, kwargs=kwargs)
        
        """
            Another temporary gnupg directory is necessary, because the other default temporary
            directory can't be locked for the MTASendThreads.
        """
        self.gnupg = GnuPGManager.GnuPGManager(homeTmp='/tmp/.gnupgMTA')
        self.timestamp = datetime.datetime.now().strftime("%A, %d. %B %Y %I:%M%p")
        self.distAddr = distAddr
        self.senderAddr = senderAddr
        self.userInfoTmp = userInfo
        self.distKeyIDSig = distKeyIDSig
        self.distKeys = distKeys
        self.addrMsgDict = addrMsgDict
        self.addrFingerprintKeyInf = addrFingerprintKeyInf
        self.sleepCounter = 0
        self.retryFirst = False
        self.recipientIsSenderFlag = False
        """
            Logging only for server-side errors to trace problems. 
        """
        self.__logger = GnuPGSystemLogger('mtaSendThread')

    def get_recipient_is_sender_flag(self):
        return self.__recipientIsSenderFlag

    def get_timestamp(self):
        return self.__timestamp

    def get_dist_addr(self):
        return self.__distAddr

    def get_sender_addr(self):
        return self.__senderAddr

    def get_user_info(self):
        return self.__userInfo

    def get_dist_key_idsig(self):
        return self.__distKeyIDSig

    def get_dist_keys(self):
        return self.__distKeys

    def get_addr_msg_dict(self):
        return self.__addrMsgDict

    def get_addr_fingerprint_key_inf(self):
        return self.__addrFingerprintKeyInf

    def get_sleep_counter(self):
        return self.__sleepCounter

    def get_retry_first(self):
        return self.__retryFirst

    def set_recipient_is_sender_flag(self, value):
        self.__recipientIsSenderFlag = value
    
    def set_timestamp(self, value):
        self.__timestamp = value

    def set_dist_addr(self, value):
        self.__distAddr = value

    def set_sender_addr(self, value):
        self.__senderAddr = value

    def set_user_info(self, value):
        self.__userInfo = value

    def set_dist_key_idsig(self, value):
        self.__distKeyIDSig = value

    def set_dist_keys(self, value):
        self.__distKeys = value

    def set_addr_msg_dict(self, value):
        self.__addrMsgDict = value

    def set_addr_fingerprint_key_inf(self, value):
        self.__addrFingerprintKeyInf = value

    def set_sleep_counter(self, value):
        self.__sleepCounter = value

    def set_retry_first(self, value):
        self.__retryFirst = value

        
    def run(self):
        threading.Thread.run(self)  
        self.__sendAllMessages()   
        
    def __sendAllMessages(self):
        """
            Iterates over the address-message-dictionary and send the message to the address.
            If it was not possible to send messages, the thread will first sleep __RETRY_FIRST_TIME 
            and try it again. If it was not possible again for some messages it will sleep __RETRY_ELSE_TIME
            until __SENDER_MSG_TIME is reached. Then the origin sender need to be informed.
            1. case: If the address-message-dictionary is set, the origin message is re-encrypted.
            2. case: If the address-message-dictionary is not set, the origin message is another message
            and has his own user-information. Then the address-message-dictionary will be created (signed and
            encrypted if it is possible or only signed).
        """
        #If the origin mail was re-encrypted, addrMsgDict is not None.
        #Otherwise it needs to be created from one the prepare methods.
        if not self.get_addr_msg_dict():
            if self.get_addr_fingerprint_key_inf():
                self.__prepareSigAndEncMsg()
            else:
                self.__prepareSigMsg()
                
        addrMsgNotEmpty = True
        addrMsgDictTmp = self.get_addr_msg_dict().copy()
        while addrMsgNotEmpty:
            for recipientAddr, mail in addrMsgDictTmp.items():
                sended = self.__sendToMTA(recipientAddr, mail)
                if sended:
                    del self.get_addr_msg_dict()[recipientAddr]
                    
            if self.get_addr_msg_dict():
                if not self.get_retry_first():
                    time.sleep(MTASendThread.__RETRY_FIRST_TIME)
                    self.set_retry_first(True)
                else:
                    if self.get_sleep_counter() * MTASendThread.__RETRY_ELSE_TIME == MTASendThread.__SENDER_MSG_TIME:
                        addrMsgNotEmpty = False
                        #If the recipient is the same as the sender it doesn't need to try it again.
                        if (not self.get_recipient_is_sender_flag()) and recipientAddr != self.get_sender_addr():
                            self.set_recipient_is_sender_flag(True)
                            self.__prepareErrorMSGForSender()
                            self.set_sleep_counter(0)
                            self.__logger.logError('COULD NOT SEND ALL MESSAGES TO RECIPIENTS\n' +
                                                   'SEND AN INFORMATION MESSAGE TO SENDER')
                            self.__sendAllMessages()
                    else:
                        time.sleep(MTASendThread.__RETRY_ELSE_TIME)
                        self.set_sleep_counter(self.get_sleep_counter() + 1)
            else:
                addrMsgNotEmpty = False
                
    def __prepareSigAndEncMsg(self):
        """
           Prepare a signed and encrypted message for the sender of the mail. It creates an 
           address-message-dictionary: {mail-address : signed and encrypted message}.
        """   
        
        try:
            #It is necessary to send the distributer keys in the attachment.
            if _util.objectsNotNone(self.get_dist_key_idsig(), self.get_dist_keys()):
                msg = _util.generateMIMEMsg('mixed', self.get_dist_keys(), None, None, None, None, optinal=self.get_user_info())
            else:
                msg = _util.generateMIMEMsg('plain', self.get_user_info(), None, None, None, None)
            
            if self.get_dist_key_idsig() is None:
                (_distKeyIDEnc, distKeyIDSig) = self.gnupg.getKeyIDsFromDist(self.get_dist_addr())
                self.set_dist_key_idsig(distKeyIDSig)
            MTASendThread.__SIGN_AND_ENCRYPTLOCK.acquire()
            addressMsgDict = self.gnupg.signAndEncrypt(self.get_addr_fingerprint_key_inf(), self.get_sender_addr(), msg, self.get_dist_addr(), '', self.get_dist_key_idsig())
            MTASendThread.__SIGN_AND_ENCRYPTLOCK.release()
        except NoDistributerKeyIDsException:
            addressMsgDict = {}
            userInfo = self.get_user_info() + '\nNO WAY TO SIGN AND ENCRYPT THIS MESSAGE' + '\nPLEASE CONTACT THE ADMINISTRATOR'
            msg = _util.generateMIMEMsg('plain', userInfo, None, self.get_dist_addr(), self.get_sender_addr(), None)
            addressMsgDict[self.get_sender_addr()] = msg
          
        self.set_addr_msg_dict(addressMsgDict)
               
    def __prepareSigMsg(self):
        """
            Prepare a signed message, if any exception occurred in the process and it was not possible
            to get informations about the sender of the mail to encrypt that message. It creates an address-
            message-dictionary: {mail-address : signed message} 
        """
        try: 
            userInfoTmp = 'FIRST ERROR: ' + self.get_user_info()
            addressMsgDict = {}
            if self.get_dist_key_idsig() is None:
                (_distKeyIDEnc, distKeyIDSig) = self.gnupg.getKeyIDsFromDist(self.get_dist_addr())
                self.set_dist_key_idsig(distKeyIDSig)
            userInfoTmp = userInfoTmp + '\nNO WAY TO ENCRYPT THIS MESSAGE' + '\nMAYBE YOU NEED TO CONTACT THE ADMINISTRATOR'
            msg = _util.generateMIMEMsg('plain', userInfoTmp, None, None, None, None)
            signature = self.gnupg.signMsg(msg, self.get_dist_key_idsig())
            msgSig = _util.generateMIMEMsg('signed', msg, signature, self.get_dist_addr(), self.get_sender_addr(), '')
            addressMsgDict[self.get_sender_addr()] = msgSig
        except (NoDistributerKeyIDsException, SigningException) as e:
            userInfoTmp = userInfoTmp + ' \nNO WAY TO SIGN AND ENCRYPT THIS MESSAGE: ' + e.__str__() + '\nPLEASE CONTACT THE ADMINISTRATOR'
            msg = _util.generateMIMEMsg('plain', userInfoTmp, None, self.get_dist_addr(), self.get_sender_addr(), None)
            addressMsgDict[self.get_sender_addr()] = msg
        self.set_addr_msg_dict(addressMsgDict)
        
    def __prepareErrorMSGForSender(self):
        """
            If it was not possible to send the re-encrypted mail to some of the recipients of the 
            distributer, it is necessary to inform the origin sender.
        """
        dm = DistributerManager.DistributerManager()
        dkm = DistributerKeyManager.DistributerKeyManager()
        userInfo = 'YOUR MESSAGE FROM ' + self.get_timestamp() + ' COULD NOT SEND TO ' + ', '.join(list(self.get_addr_msg_dict().keys()))
        self.set_user_info(userInfo)
        self.set_dist_keys(None)
        addrFingerprintKeyInf = {}
        try:
            senderFingerprint = dm.getFingerprint(self.get_sender_addr(), self.get_dist_addr())
            senderKey = dkm.getKeyFromUser(senderFingerprint)
            addrFingerprintKeyInf[self.get_sender_addr()] = (senderFingerprint, senderKey)
            self.set_addr_fingerprint_key_inf(addrFingerprintKeyInf)
            self.__prepareSigAndEncMsg()
        except (InvalidDistributerAddressException, NoFingerprintException, DBConnectionException, NoKeyException):
            self.__prepareSigMsg()

    def __sendToMTA(self, recipientAddr, mail):
        """
            Send the message to the MTA of the recipient's mail provider. If it failed, it will be logged.
            @param recipientAddr: Mail address of the recipient.
            @param mail: The MIME-mail to send to the recipient.
        """
        server = None
        counter = 0
        try:
            records = _util.getMXRecords(recipientAddr)
            for rec in records:
                domain = str(rec.exchange)
                server = smtplib.SMTP(domain)
                #server.set_debuglevel(1)
                server.starttls()
                try:
                    server.sendmail(self.get_dist_addr(), recipientAddr, mail.as_string())
                    break
                except (SMTPSenderRefused, SMTPRecipientsRefused, SMTPDataError) as e:
                    """
                        No sendmail possible
                    """
                    self.__logger.logError(e.__str__())
                    counter += 1
                    if counter == len(records):
                        return False
                
            return True
        except NoMXRecordException as e:
            """
                Could not solve the MX-Record.
            """
            self.__logger.logError(e.__str__())
        except socket.gaierror as e:
            """
                No SMTP instance.
            """
            self.__logger.logError(e.__str__())
        except (RuntimeError, ValueError) as e:
            """
                No STARTTLS possible
            """
            self.__logger.logError(e.__str__())
        finally:
            if server is not None:
                server.quit() 
        return False
    
    timestamp = property(get_timestamp, set_timestamp, None, None)
    distAddr = property(get_dist_addr, set_dist_addr, None, None)
    senderAddr = property(get_sender_addr, set_sender_addr, None, None)
    userInfoTmp = property(get_user_info, set_user_info, None, None)
    distKeyIDSig = property(get_dist_key_idsig, set_dist_key_idsig, None, None)
    distKeys = property(get_dist_keys, set_dist_keys, None, None)
    addrMsgDict = property(get_addr_msg_dict, set_addr_msg_dict, None, None)
    addrFingerprintKeyInf = property(get_addr_fingerprint_key_inf, set_addr_fingerprint_key_inf, None, None)
    sleepCounter = property(get_sleep_counter, set_sleep_counter, None, None)
    retryFirst = property(get_retry_first, set_retry_first, None, None)
    recipientIsSenderFlag = property(get_recipient_is_sender_flag, set_recipient_is_sender_flag, None, None)      
