'''
Created on 13.06.2016

@author: Fabian Reiber
@version: 1.0
'''

from enum import Enum


class SubjectCommand(Enum):
    ADDTODIST = 'ADDTODIST'
    CHANGEPK = 'CHANGEPK'
    DELFROMDIST = 'DELFROMDIST'
    GETPK = 'GETPK'
    REENCRYPT = 'REENCRYPT'
    
    def __str__(self):
        return str(self.value)