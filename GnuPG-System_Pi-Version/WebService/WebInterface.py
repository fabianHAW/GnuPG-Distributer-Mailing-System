'''
Created on 13.06.2016

@author: Fabian Reiber
@version: 1.0
The WebInterface module for an administrator to subscribe or unsubscribe member to or from a distributer.
'''

import sys

from DistributerKeyManagement import DistributerKeyManager
from DistributerKeyManagementException.KeyDeleteException import KeyDeleteException
from DistributerKeyManagementException.NoAddedKeyException import NoAddedKeyException
from DistributerManagement import DistributerManager
from DistributerManagementException.DBConnectionException import DBConnectionException
from DistributerManagementException.InvalidDistributerAddressException import InvalidDistributerAddressException
from GnuPGManagementCenter import GnuPGManager
from GnuPGManagementCenterException.ExtractFingerprintException import ExtractFingerprintException
from GnuPGManagementCenterException.NoDistributerKeyIDsException import NoDistributerKeyIDsException
from GnuPGManagementCenterException.NoDistributerKeysException import NoDistributerKeysException
from MailDistributionCenter.MTASendThread import MTASendThread
from email.utils import parseaddr
from DistributerManagementException.NoFingerprintException import NoFingerprintException

def subscribe(userAddr, distAddr, key):
    """
        Subscribe a given mail-address and PGP-key to a given distributer address.
        @param userAddr: The given mail-address to add.
        @param distAddr: The given distributer address.
        @param key: The PGP-key of the mail-address.
        @raise ExtractFingerprintException: If the fingerprint could not be extracted, it prints the exception.
        @raise NoAddedKeyException: If the key could not be added, it prints the exception.
        @raise InvalidDistributerAddressException: If the distributer address is not right, it prints the exception.
        @raise DBConnectionException: If it was not possible to connect to the database, it prints the exception.
        @raise NoDistributerKeyIDsException: If the key-ids of the distributer are not found, it prints the exception.
        @raise NoDistributerKeysException: If the keys of the distributer are not given, it prints the exception.
        @raise NoFingerprintException: If the fingerprint is rigth, it prints the exception.
        @raise KeyDeleteException: If it was not possible to delete the key (while undoing), it prints the exception.
    """
    
    dm = DistributerManager.DistributerManager()
    dkm = DistributerKeyManager.DistributerKeyManager()
    gnupg = GnuPGManager.GnuPGManager()
    userInfo = ''
    addrFingerprintKeyInf = {}
        
    try:        
        fingerprint = gnupg.extractFingerprint(key)
        dkm.addNewKey(key)
        dm.addNewAddr(userAddr, distAddr, fingerprint)
        userInfo += 'ADDED ' + userAddr + ' SUCCESSFUL TO ' + distAddr
        (keyIDEnc, keyIDSig) = gnupg.getKeyIDsFromDist(distAddr)
        distKeys = gnupg.getKeysFromDist(keyIDEnc, keyIDSig)
        print(userInfo)
        userInfo += '\nYOU FIND THE KEYS FOR ' + distAddr + ' IN THE ATTACHMENT'
        addrFingerprintKeyInf[userAddr] = (fingerprint, key)
        thread = MTASendThread(distAddr, userAddr, userInfo, addrFingerprintKeyInf, keyIDSig, distKeys, {})
        thread.start()
    except ExtractFingerprintException as e:
        print(e.__str__())
    except NoAddedKeyException as e:
        print(e.__str__())
    except (InvalidDistributerAddressException, DBConnectionException, NoDistributerKeyIDsException, NoDistributerKeysException, NoFingerprintException) as e:
        try:
            # Undo add-operation
            dm.delAddrFromDist(userAddr, distAddr)
            dkm.delKeyFromServer(fingerprint)
            print(e.__str__())
        except (KeyDeleteException, DBConnectionException) as ee:
            print(e.__str__())
            print('\nWHILE UNDOING, ANOTHER EXCEPTION OCCURRED: ', ee.__str__())
    
def unsubscribe(userAddr, distAddr, deleteKey):
    """
        Unsubscribe a given mail-address and PGP-key (if deleteKey is 1) to a given distributer address.
        @param userAddr: The given mail-address to add.
        @param distAddr: The given distributer address.
        @param deleteKey: If it is 0, the PGP-key of the given mail-address will not delete. If it is 1, it will
        delete the key.
        @raise Exception: If there occured any exception, it prints the exception.
    """
    
    dm = DistributerManager.DistributerManager()
    dkm = DistributerKeyManager.DistributerKeyManager()
    userInfo = ''
    addrFingerprintKeyInf = {}
        
    try:
        fingerprint = dm.getFingerprint(userAddr, distAddr)
        userKey = dkm.getKeyFromUser(fingerprint)
        dm.delAddrFromDist(userAddr, distAddr)
        if deleteKey == 1:
            dkm.delKeyFromServer(fingerprint)
        userInfo = 'DELETED ' + userAddr + ' SUCCESSFUL FROM ' + distAddr
        addrFingerprintKeyInf[userAddr] = (fingerprint, userKey)
        print(userInfo)
        thread = MTASendThread(distAddr, userAddr, userInfo, addrFingerprintKeyInf, None, None, {})
        thread.start()
    except Exception as e:
        # Undo is not necessary
        print('AN EXCEPTION OCCURRED: ', e.__str__())

def checkMailAddresses(userAddr, distAddr):
    """
        Check if the given addresses have a right mail-address format.
        @param userAddr: A given mail-address of a user to check.
        @param distAddr: A given distributer address to check.  
        @return: Returns True if the addresses have a right format, else False.
    """
    
    userAddrParsed = parseaddr(userAddr)[1]
    distAddrParsed = parseaddr(distAddr)[1]
    userAddrSplit = userAddrParsed.rsplit('@')
    distAddrSplit = distAddrParsed.rsplit('@')
    if len(userAddrSplit) == 2 and len(distAddrSplit) == 2:
        userDomainPart = userAddrSplit[1].rsplit('.')
        distDomainPart = distAddrSplit[1].rsplit('.')
        if len(userDomainPart) >= 2 and len(distDomainPart) >= 2:
        #The length of the local-part is at least 1.
        #The domain-part needs to have a dot in it. Before and after this dot it needs to have a length of at least 1
            if len(userAddrSplit[0]) > 0 and len(userDomainPart[0]) > 0 and len(userDomainPart[1]) > 0:
                if len(distAddrSplit[0]) > 0 and len(distDomainPart[0]) > 0 and len(distDomainPart[1]) > 0:
                    return True
    return False

if len(sys.argv) == 5:
    if checkMailAddresses(sys.argv[2], sys.argv[3]):
        if sys.argv[1] == 'subscribe':
            subscribe(sys.argv[2], sys.argv[3], str(sys.argv[4]))
        elif sys.argv[1] == 'unsubscribe':
            unsubscribe(sys.argv[2], sys.argv[3], int(sys.argv[4]))
    else:
        print('E-MAIL AND/OR DISTRIBUTER ARE NOT A VALID ADDRESS')
else:
    print('YOU NEED TO FILL OUT THE FIELDS')

print('\n\nREDIRECT AFTER 5 SECONDS...')
