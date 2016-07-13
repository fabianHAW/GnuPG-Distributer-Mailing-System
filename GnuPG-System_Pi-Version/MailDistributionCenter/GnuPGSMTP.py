'''
Created on 13.06.2016

@author: Fabian Reiber
@version: 1.0
This module starts the SMTPChannel. It also can stop it with a SIGTERM.
'''

import signal
import sys
import asyncore

from MailDistributionCenter.SMTPChannel import SMTPChannel
from util import _util

class GnuPGSMTP(object):
    
    __LOCAL_HOST_ADDR =  _util.getIPAddress('wlan0')
    __LOCAL_PORT = 2525
    
    def start(self):
        """
            Instantiate the SMTP channel on Port 2525 and starts listening with asyncore.
        """
        signal.signal(signal.SIGTERM, self.__sigTermHandler)
        self.smtpChannel = SMTPChannel((GnuPGSMTP.__LOCAL_HOST_ADDR, GnuPGSMTP.__LOCAL_PORT), None)
        
        try:
            print('Server started')
            asyncore.loop()
        except:
            self.stop()
            
    def stop(self):
        """
            Stop the SMTP channel.
        """
        self.smtpChannel.close()
        print('Server stopped')
        
    def __sigTermHandler(self, signal, frame):
        """
            Handler for SIGTERM to close the SMTP channel.
        """
        sys.exit(0)

server = GnuPGSMTP()
server.start()