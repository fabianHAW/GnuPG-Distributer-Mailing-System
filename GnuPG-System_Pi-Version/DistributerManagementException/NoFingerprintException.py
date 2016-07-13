'''
Created on 13.06.2016

@author: Fabian Reiber
@version: 1.0
'''

class NoFingerprintException(Exception):
    def __str__(self, *args, **kwargs):
        return Exception.__str__(self, *args, **kwargs)
#     
# a = NoFingerprintException('Blaa')   
# print('test:', a.args[0]) 
# raise a
