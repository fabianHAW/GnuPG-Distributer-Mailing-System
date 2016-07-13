'''
Created on 13.06.2016

@author: Fabian Reiber
@version: 1.0
'''

from enum import Enum
 
class MSGStatus(Enum):
    DEC_OK = 'decryption ok'
    VER_OK = 'signature valid'
    SIG_OK = 'begin signing'
    DEC_NOT_OK = 'decryption failed'
    
    def __str__(self):
        return str(self.value)
