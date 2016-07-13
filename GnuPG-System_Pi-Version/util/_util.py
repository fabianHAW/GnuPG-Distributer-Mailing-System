'''
Created on 13.06.2016

@author: Fabian Reiber
@version: 1.0
This helper-module offers some helpful methods for the GnuPG-System.
'''

import base64
from dns.resolver import NXDOMAIN, YXDOMAIN, NoAnswer, NoNameservers, \
    NoMetaqueries, Timeout
import dns.resolver
from email.message import Message
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr
import netifaces

from utilException.InvalidKeyException import InvalidKeyException
from utilException.NoEncryptionPartException import NoEncryptionPartException
from utilException.NoMXRecordException import NoMXRecordException
from utilException.NoSignedPartException import NoSignedPartException

"""
    The possible PGP-Hash-Algorithms.
"""
__GNUPG_ALGO = {
        '1' : 'pgp-md5',
        '2' : 'pgp-sha1',
        '3' : 'pgp-ripemd160',
        '8' : 'pgp-sha256',
        '9' : 'pgp-sha384',
        '10' : 'pgp-sha512',
        '11' : 'pgp-sha224'
        }

def extractKey(msgList):
    """
        Extract a PGP-key from a given MIME message.
        @param msgList: The messages in a List in MIME format.
        @raise InvalidKeyException: If there is no key in the MIME part.
        @return: The extracted key.
    """
    keyValid = False
    for elem in msgList:
        for subPart in elem.walk():
            key = subPart.get_payload(decode=True)
            if __checkIfKey(key):
                keyValid = True
                break
        if keyValid:
            return key
    else:
        raise InvalidKeyException('KEY INVALID')
    
def generateMIMEAttachmentPart(part, partTmp, filename):
    """
        Generates the PGP-Attachment-MIME-Part.
        @param part: The decrypted content of the attachment.
        @param partTmp: The origin attachment in MIME format.
        @param filename: The filename of the attachment.
        @return: An attachment MIME part.
    """
    attachment = Message()
    attachment['Content-Type'] = partTmp.get_content_type() + filename
    attachment['Content-Disposition'] = partTmp.get("Content-Disposition", None)
    attachment['Content-Transfer-Encoding'] = 'base64'
    attachment.set_payload(base64.b64encode(part))
    return attachment

def generateMIMEEncryptionPart(enc):
    """
        Generates the encrypted-MIME-Part.
        @param enc: The encrypted message.
        @return: A pgp-encrypted MIME part.
    """
    encMime = Message()
    encMime['Content-Type'] = 'application/octet-stream; name="encrypted.asc"'
    encMime['Content-Description'] = 'OpenPGP encrypted message'
    encMime.set_payload(str(enc))
    return encMime

def generateMIMEKeyPart(key):
    """
        Generates the PGP-Key-MIME-Part.
        @param key: The key for the MIME part.
        @return: A pgp-keys MIME part.
    """
    keyMime = Message()
    keyMime['Content-Type'] = 'application/pgp-keys; name=keys.asc'
    keyMime['Content-Disposition'] = 'attachment; filename=\'keys.asc\''
    keyMime.set_payload(str(key))
    return keyMime

def generateMIMEMsg(subtype, msg, signature, senderAddr, recipientAddr, subject, optinal=None):
    """
        Generates a MIME message depending on the subtype.
        @param subtype: The subtype of the MultipartMIME message.
        @param msg: The message part for the MIME message.
        @param signature: The signature of the given message part.
        @param senderAddr: The sender mail-address of that message.
        @param recipientAddr: The recipient mail-address of the message.
        @param subject: The subject for the message
        @param optional: An additional message for the message, e.g. the public-keys of a distributer.
        @return: The MultipartMIME message, or a simple MIME text message.
    """
    multiMime = MIMEMultipart(_subtype=subtype)
    if subtype == 'signed':
        sigAlg = __GNUPG_ALGO.get(signature.sig_hash_algo)
        sigPart = generateMIMESignaturePart(signature)
        multiMime.set_param(param='protocol', value='application/pgp-signature')
        multiMime.set_param(param='micalg', value=sigAlg)
        multiMime.attach(msg)
        multiMime.attach(sigPart)
        if subject is '':
            # If a message exclusively is signed and not encrypted. 
            multiMime.add_header('To', formataddr((recipientAddr, recipientAddr)))
            multiMime.add_header('From', formataddr((senderAddr, senderAddr)))
            multiMime.add_header('Subject', '')
    elif subtype == 'encrypted':
        firstPart = MIMEApplication(_data='', _subtype="pgp-encrypted")
        encPart = generateMIMEEncryptionPart(msg)
        multiMime.set_param(param='protocol', value='application/pgp-encrypted')
        multiMime.attach(firstPart)
        multiMime.attach(encPart)
        multiMime.add_header('To', formataddr((recipientAddr, recipientAddr)))
        multiMime.add_header('From', formataddr((senderAddr, senderAddr)))
        multiMime.add_header('Subject', subject)
    elif subtype == 'plain':
        textPart = MIMEText(msg)
        if (recipientAddr is not None) and (senderAddr is not None):
            # If the message will send without a signature.
            textPart.add_header('To', formataddr((recipientAddr, recipientAddr)))
            textPart.add_header('From', formataddr((senderAddr, senderAddr)))
            textPart.add_header('Subject', '')
        return textPart
    elif subtype == 'mixed':
        firstPart = MIMEText(optinal)
        keyPart = generateMIMEKeyPart(msg)
        multiMime.attach(firstPart)
        multiMime.attach(keyPart) 
        
    return multiMime

def generateMIMESignaturePart(sig):
    """
        Generates the signature-MIME-Part.
        @param sig: The signature of a message.
        @return: A pgp-signature MIME part.
    """
    sigMime = Message()
    sigMime['Content-Type'] = 'application/pgp-signature; name="signature.asc"'
    sigMime['Content-Description'] = 'OpenPGP digital signature'
    sigMime.set_payload(str(sig))
    return sigMime

def getMIMEPartEnc(msg):
    """
        Separates a PGP-Mime-Encrypted or Inline-PGP message in the existing MIME-Parts.
        @param msg: The encrypted message in MIME-Format.
        @raise NoEncryptionPartException: If there is no encrypted part found.
        @return: 2-Tuple: 1.element := partType (mime or inline), 
        2. element := the encrypted part of the MIME message.
    """
    encrytedPartList = list()
    msgConsist = False
    #Check if message is PGP/MIME
    for part in msg.walk():
        if part.get_content_type() == 'application/pgp-encrypted':
            msgConsist = True
        elif (part.get_content_type() == 'application/octet-stream') and msgConsist:
            encrytedPartList.append(part.get_payload(decode=True))
            
    if encrytedPartList:
        return ('mime', encrytedPartList)
    
    else:
        """
            If the MIME message is not PGP/MIME, it is possible that
            the message has the Inline-PGP format.
        """
        #It needs to be at least one PGP specific message part in the origin mail. 
        encPartFound = False
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if not encPartFound:
                if __checkIfPGPMsg(part.get_payload(decode=True)):
                    encrytedPartList.append(part)
                    encPartFound = True
                else:
                    break
            else:
                encrytedPartList.append(part)
    
    if not encrytedPartList:
            raise NoEncryptionPartException('NO ENCRYPTED PART FOUND IN MAIL')
        
    return ('inline', encrytedPartList)

def getMIMEPartsSig(msg):
    """
        Separates a PGP-Mime-Signature message in the existing MIME-Parts.
        @param msg: The signed message in MIME-Format.
        @raise NoSignedPartException: If there is no signed part found.
        @return: 2-Tuple: 1.element := partType (mime or inline), 
        2. element := a message-dictionary: key := signed message; value := signature of message.
    """
    msgSig = None
    sig = None
    mailType = ''
    sigDict = {}
    
    if msg.get_content_type() == 'multipart/signed':
        #MIME-format
        for part in msg.walk():
            if part.is_multipart() and part.get_content_subtype() != 'signed':
                msgSig = part
            elif part.get_content_type() == 'application/pgp-signature':
                sig = part.get_payload(decode=True) 
            elif (msgSig is None) and (part.get_content_type() != 'multipart/signed') and (part.get_content_type() != 'application/pgp-signature'):   
                #If part has another MIME-format as multipart/signed or application/pgp-signature
                msgSig = part
        if objectsNotNone(msgSig, sig):
            sigDict[msgSig] = sig
            mailType = 'mime'
        else:
            raise NoSignedPartException('NO SIGNED PART FOUND IN MAIL')
    else:
        #Inline-format
        attach = None
        mailType = 'inline'
        for part in msg.walk():
            if part.is_multipart():
                continue
            dispo = part.get('Content-Disposition', '')
            if dispo.startswith('attachment'):
                if attach is None:
                    #Set the signed part
                    attach = part
                    sigDict[attach] = None
                else:
                    #Set the signature for the signed part
                    sigDict[attach] = part
                    attach = None
            else:
                sigDict[part] = None
                
    return (mailType, sigDict)

def getIPAddress(interface):
    """
        Determine the IP-address of a given interface.
        @param interface: The given interface.
        @return: IP-address for the interface.
    """
    return netifaces.ifaddresses(interface)[2][0]['addr']

def getMXRecords(userAddr):
    """
        Returns a list of all available MX-Records of a specific domain.
        @param userAddr: A mail-address to search the MX-records for.
        @raise NoMXRecordException: If there occurred DNS specific error.
        @return: A list of all MX-Records for the given domain.
    """
    domain = userAddr.rsplit('@')[-1]
    try:
        return dns.resolver.query(domain, 'MX')
    except (Timeout, NXDOMAIN, YXDOMAIN, NoAnswer, NoNameservers, NoMetaqueries) as e:
        raise NoMXRecordException(e.__str__())

def objectsNotNone(*objs):
    """
        Checks if a tuple of objects is None.
        @param *objs: Tuple of objects to check.
        @return: False, if one object is None, else True.
    """
    for obj in objs:
        if obj is None:
            return False
    return True

def __checkIfKey(key):
    """
        Helper-Method: Check if a given key starts and ends witch the specific PGP key block syntax.
        @param key: The key to check.
        @return: True if it is a valid PGP key, else False.
    """
    if key is not None:
        if key.strip().startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----'):
            return key.strip().endswith(b'-----END PGP PUBLIC KEY BLOCK-----')
    return False

def __checkIfPGPMsg(msg):
    """
        Helper-Method: Check if a given decoded messages starts and ends witch the specific 
        PGP message block syntax.
        @param msg: The message to check.
        @return: True if it is a valid PGP message, else False.
    """
    if msg.strip().startswith(b'-----BEGIN PGP MESSAGE-----'):
        return msg.strip().endswith(b'-----END PGP MESSAGE-----')
    return False
