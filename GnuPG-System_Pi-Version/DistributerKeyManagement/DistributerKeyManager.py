'''
Created on 13.06.2016

@author: Fabian Reiber
@version: 1.0
This module has the access to the SKS Key-Server which is running on Port 11371. 
'''

import requests, re, subprocess

from DistributerKeyManagementException.KeyDeleteException import KeyDeleteException
from DistributerKeyManagementException.NoAddedKeyException import NoAddedKeyException
from DistributerKeyManagementException.NoKeyException import NoKeyException
from util.GnuPGSystemLogger import GnuPGSystemLogger
from util import _util


class DistributerKeyManager:
    
    __HOST = 'http://' + _util.getIPAddress('wlan0') + ':11371/pks/'
    __STATUS_CODE_OK = 200
    
    def __init__(self):
        """
            Logging only for server-side errors to trace problems. 
        """
        self.__logger = GnuPGSystemLogger('distributerKeyManager')
        
    def addNewKey(self, key):
        """
            Add a given key.
            @param key: The new key to add on server.
            @raise NoAddedKeyException: If the server could not add the key.
        """
        post = requests.post(DistributerKeyManager.__HOST + 'add', data={'keytext': key})
        if post.status_code != DistributerKeyManager.__STATUS_CODE_OK:
            self.__logger.logError('status_code: ' + str(post.status_code))
            raise NoAddedKeyException('COULD NOT ADD KEY ON KEY SERVER')
    
    def changeKeyOnServer(self, fingerprint, key):
        """
            First delete the key on server corresponding with the fingerprint and then add the new key.
            If It was not possible to add the new key, the old key will be saved again.
            @param fingerprint: Fingerprint to identify the key to delete.
            @param key: The new key to add on server.
        """
        try:
            keyOld = self.getKeyFromUser(fingerprint)
            self.delKeyFromServer(fingerprint)
            self.addNewKey(key)
        except NoKeyException as e:
            raise NoKeyException(e.__str__() + '. YOUR ADDRESS COULD NOT FIND ON THIS DISTRIBUTER')
        except KeyDeleteException as e:
            raise e
        except NoAddedKeyException as e:
            self.addNewKey(keyOld)
            raise e
        
    def delKeyFromServer(self, fingerprint):
        """
            Delete a key by given fingerprint.
            @param fingerprint: The fingerprint for the key.
            @raise KeyDeleteException: If the key could not delete.
        """
        get = requests.get(DistributerKeyManager.__HOST + 'lookup?hash=on&search=0x' + fingerprint)
        if get.status_code == DistributerKeyManager.__STATUS_CODE_OK:
            hashID = re.findall('search=(\w*)', get.text)
            try:
                subprocess.call(["sudo", "sks", "drop", hashID[2]])
            except RuntimeError as e:
                self.__logger.logError(e.__str__())
                raise KeyDeleteException('COULD NOT DELETE KEY ON KEY SERVER')
    
    def getKeyFromUser(self, fingerprint):
        """
            Find a key by given fingerprint.
            @param fingerprint: The fingerprint to find the key.
            @raise NoKeyException: If the server did not find the key.
            @return: The founded key.
        """
        get = requests.get(DistributerKeyManager.__HOST + 'lookup?op=get&options=mr&search=0x' + fingerprint)
        if get.status_code == DistributerKeyManager.__STATUS_CODE_OK:
            key = re.findall('<pre>(.*?)</pre>', get.text, re.DOTALL)
            return key[0]
        raise NoKeyException('NO KEY FOUND ON KEY SERVER')
    
    def getKeyInfFromUsers(self, addressFingerprintList):
        """
            Generates a dictionary: {mail-Address : (fingerprint, key)}. This represents given informations
            about an E-Mail address.
            @param: A 2-tuple-element list (mail-address, fingerprint)
            @raise NoKeyException: If the server did not find the key.
        """
        addrFingerprintKeyInf = {}
        for (address, fingerprint) in addressFingerprintList:
            try:
                key = self.getKeyFromUser(fingerprint)
                addrFingerprintKeyInf[address] = (fingerprint, key)
            except NoKeyException as e:
                raise NoKeyException(e.__str__())
        return addrFingerprintKeyInf
