'''
Created on 13.06.2016

@author: Fabian Reiber
@version: 1.0
This module has the access to the distributer database.
'''
import MySQLdb

from DistributerManagementException.DBConnectionException import DBConnectionException
from DistributerManagementException.InvalidDistributerAddressException import InvalidDistributerAddressException
from DistributerManagementException.NoFingerprintException import NoFingerprintException
from DistributerManagementException.NoUserException import NoUserException
from util.GnuPGSystemLogger import GnuPGSystemLogger


class DistributerManager:
    
    __DBCONF = '/home/pi/smtpserver/GnuPG-System_Pi-Version/DistributerManagement/.db_config.cnf'
    
    def __init__(self):
        """
            Logging only for server-side errors to trace problems. 
        """
        self.__logger = GnuPGSystemLogger('distributerManager')
    
    def addNewAddr(self, userAddr, distAddr, fingerprint):
        """
            Add a new mail-address to a distributer. Also add the corresponding fingerprint. Only
            if the given distributer is valid, the Helper-Method will add the new address.
            @param userAddr: Mail-address to add on distributer.
            @param distAddr: Distributer address on which the mail-address add to.
            @param fingerprint: Fingerprint of the given mail-address.
            @raise NoFingerprintException: If the fingerprint is not 40 characters long.
            @raise InvalidDistributerAddressException: If the given distributer address is not available.
            @raise DBConnectionException: If it is not possible to connect to the database.
        """
        try:
            db = None
            cursor = None
            (db, cursor) = self.__connectDB()
            distList = self.__getAllDist(cursor)
            if (distAddr,) in distList:
                fingerprintEncoded = fingerprint.encode('UTF-8')
                if len(fingerprintEncoded) == 40:
                    self.__addToDist(cursor, userAddr, distAddr, fingerprintEncoded)
                else:
                    raise NoFingerprintException('THE FINGERPRINT MUST BE 40 CHARACTER LONG')
            else:
                raise InvalidDistributerAddressException('DISTRIBUTERADDRESS INVALID')
        except DBConnectionException as e:
            raise DBConnectionException(e.__str__())
        finally:
            self.__closeDB(db, cursor)
            
    def changeFingerprint(self, userAddr, distAddr, fingerprint):
        """
            Change a given fingerprint for a mail-address on a distributer.
            @param userAddr: Mail-address to change fingerprint for.
            @param distAddr: Distributer address on which the mail-address should be member.
            @param fingerprint: The new fingerprint.
            @raise NoFingerprintException: If the fingerprint is not 40 characters long.
            @raise DBConnectionException: If it is not possible to connect to the database.
        """
        try:
            db = None
            cursor = None
            fingerprintEncoded = fingerprint.encode('UTF-8')
            if len(fingerprintEncoded) == 40:
                (db, cursor) = self.__connectDB()
                cursor.execute(
                """
                    UPDATE distributer_mail_address dma, distributer d, mail_address ma 
                    SET dma.fingerprint = %s 
                    WHERE ma.address = %s 
                    AND d.address = %s 
                    AND dma.maID = ma.maID 
                    AND dma.distID = d.distID
                """, (fingerprintEncoded, userAddr, distAddr))
            else:
                raise NoFingerprintException('THE FINGERPRINT MUST BE 40 CHARACTER LONG')
        except DBConnectionException as e:
            raise DBConnectionException(e.__str__())
        finally:
            self.__closeDB(db, cursor)    
    
    def delAddrFromDist(self, userAddr, distAddr):
        """
            Delete a given mail-address from a distributer. If the mail-address is not on other
            distributer, it will irrepealable deleted from the system.
            @param userAddr: Mail-address to delete.
            @param distAddr: Distributer address, on which the mail-address is member.
            @raise DBConnectionException: If it is not possible to connect to the database.
            
        """
        try:
            db = None
            cursor = None
            (db, cursor) = self.__connectDB()
            cursor.execute(
            """
                DELETE dma 
                FROM distributer_mail_address dma, mail_address ma, distributer d 
                WHERE ma.address = %s 
                AND d.address = %s 
                AND dma.maID = ma.maID AND dma.distID = d.distID
            """, (userAddr, distAddr))
              
            counter = self.__countAddrOnOtherDist(cursor, userAddr)
            if counter == 0:
                cursor.execute(
                """
                    DELETE 
                    FROM mail_address 
                    WHERE address = %s
                """, (userAddr,))
                return True
            return False
        except DBConnectionException as e:
            raise DBConnectionException(e.__str__())
        finally:
            self.__closeDB(db, cursor)
            
    def getAllAddressesWithFingerprint(self, distAddr, senderAddr):
        """
            Generates a list of 2-tuple with all mail-addresses on a distributer and corresponding fingerprint.
            @param distAddr: Distributer address where the sender address is member.
            @param senderAddr: Sender mail-address which should be member on given distributer.
            @raise DBConnectionException: If it is not possible to connect to the database.
            @return: The 2-tuple-list: [(mail-address, fingerprint)...]
        """
        try:
            db = None
            cursor = None
            (db, cursor) = self.__connectDB()
            cursor.execute(
            """
                SELECT ma.address, dma.fingerprint 
                FROM distributer d, mail_address ma, distributer_mail_address dma 
                WHERE d.address = %s 
                AND ma.address != %s 
                AND d.distID = dma.distID AND ma.maID = dma.maID
            """, (distAddr, senderAddr))
            resultTuple = cursor.fetchall()
            
            tupleList = [tuple(list(element)) for element in resultTuple]
            return tupleList
        except DBConnectionException as e:
            raise DBConnectionException(e.__str__())
        finally:
            self.__closeDB(db, cursor)
    
    def getFingerprint(self, userAddr, distAddr):
        """
            Determines the fingerprint of a given mail-address and distributer.
            @param userAddr: The mail-address to find the fingerprint.
            @param distAddr: Given distributer address on which the mail-address should be member.
            @raise InvalidDistributerAddressException: If the given distributer address is not available.
            @raise NoFingerprintException: If the fingerprint was not found.
            @raise DBConnectionException: If it is not possible to connect to the database.
            @return: The fingerprint of given mail-address on given distributer.
        """
        try:
            db = None
            cursor = None
            (db, cursor) = self.__connectDB()            
            cursor.execute(
            """
                SELECT dma.fingerprint 
                FROM distributer_mail_address dma, mail_address ma, distributer d 
                WHERE ma.address = %s 
                AND d.address = %s  
                AND dma.maID = ma.maID AND dma.distID = d.distID
            """, (userAddr, distAddr))
            fingerprint = cursor.fetchone()
            if fingerprint is not None:
                return fingerprint[0]
            else:
                cursor.execute(
                """
                    SELECT EXISTS(SELECT 1 
                    FROM distributer 
                    WHERE address = %s)
                """, (distAddr,))
                (result,) = cursor.fetchone()
                if result != 1:
                    raise InvalidDistributerAddressException('DISTRIBUTERADDRESS INVALID')
                else:
                    raise NoFingerprintException('NO FINGERPRINT FOUND')
        except DBConnectionException as e:
            raise DBConnectionException(e.__str__())
        finally:
            self.__closeDB(db, cursor)

    def isSenderOnDist(self, userAddr, distAddr):
        """
            Check if a mail-address is member of a given distributer.
            @param userAddr: Mail-address to check.
            @param distAddr: Distributer address on which the mail-address should be member.
            @raise NoUserException: If the mail-address could not found in database.
            @raise DBConnectionException: If it is not possible to connect to the database.
        """
        try:
            db = None
            cursor = None
            (db, cursor) = self.__connectDB()
            cursor.execute(
            """
                SELECT EXISTS(SELECT 1 
                FROM distributer d, distributer_mail_address dma, mail_address ma 
                WHERE ma.address = %s  
                AND d.address = %s 
                AND ma.maID = dma.maID AND d.distID = dma.distID)
            """, (userAddr, distAddr))
            (result,) = cursor.fetchone()
            if result != 1:
                raise NoUserException('USER IS NOT ON DISTRIBUTER') 
        except DBConnectionException as e:
            raise DBConnectionException(e.__str__())
        finally:
            self.__closeDB(db, cursor)
            
    def __addToDist(self, cursor, userAddr, distAddr, fingerprint):
        """
            Helper-Method: Add the new address and also add the relation of mail-address and distributer.
            @param cursor: Cursor for execute the query.
            @param userAddr: Given mail-address to add.
            @param distAddr: Given distributer address where the mail-address will be member.
            @param fingerprint: Corresponding fingerprint to mail-address.
        """
        cursor.execute(
        """
            INSERT IGNORE INTO mail_address (address) 
            VALUES(%s)
        """, (userAddr,))

        cursor.execute(
        """
            INSERT IGNORE INTO distributer_mail_address 
            VALUES ((
                SELECT distID 
                FROM distributer 
                WHERE address = %s)
            , (
                SELECT maID 
                FROM mail_address WHERE address = %s)
            , %s)
        """, (distAddr, userAddr, fingerprint))
    
    def __closeDB(self, db, cursor):
        """
            Close the given database connection.
            @param db: Database object to close.
            @param cursor: Cursor object to close.
            @raise Exception: If there occurs any Exception. It will also be logged.
        """
        try:
            cursor.close()
            db.close()
        except Exception as e:
            self.__logger.logError(e.__str__())
        
    def __connectDB(self):
        """
            Establish a connection to the database. The login details are in __DBCONF-file.
            @raise DBConnectionException: If it is not possible to connect to the database.
            This Exception will be logged.
            @return: The database object and a cursor object.
        """
        try:
            db = MySQLdb.connect(read_default_file=DistributerManager.__DBCONF)
            db.autocommit(True)
            cursor = db.cursor()
        except Exception as e:
            self.__logger.logError(e.__str__())
            raise DBConnectionException('NO CONNECTION TO DATABASE POSSIBLE')
        return (db, cursor)

    def __countAddrOnOtherDist(self, cursor, userAddr):
        """
            Helper-Method: count the distributer on which a mail-address is member.
            @param cursor: Cursor for executing the query.
            @param userAddr: Mail-address to check.
            @return: The counted distributer.
        """
        cursor.execute(
        """
            SELECT COUNT(distID) 
            FROM distributer_mail_address dma, mail_address ma 
            WHERE ma.address = %s 
            AND dma.maID = ma.maID
        """, (userAddr,))
        return cursor.fetchone()[0]
    
    def __getAllDist(self, cursor):
        """
            Helper-Method: Ask for every distributer in the database.
            @param cursor: Cursor for executing the query.
            @return: All founded distributer.
        """
        cursor.execute(
        """
            SELECT address 
            FROM distributer
        """)
        return cursor.fetchall()
