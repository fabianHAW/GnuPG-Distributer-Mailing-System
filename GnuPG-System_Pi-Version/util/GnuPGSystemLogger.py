'''
Created on 13.06.2016

@author: Fabian Reiber
@version: 1.0
A logger-module to log some server-side errors.
'''
import logging.config


class GnuPGSystemLogger:
    def __init__(self, loggerName):
        logging.config.fileConfig('/home/pi/smtpserver/GnuPG-System_Pi-Version/util/.log.conf')
        self.__logger = logging.getLogger(loggerName)
        
    def logError(self, msg):
        self.__logger.error(msg)