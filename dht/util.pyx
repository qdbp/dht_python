# cython: profile=True
from hashlib import sha1
import re
from socket import inet_ntoa, inet_aton

from libc.stdlib cimport atoi

cimport cython

DHT_LPORT = 37888
OUR_TOKEN = b'\x88'
OUR_T = b'\x77'
SALT = b'\x13\x37' + int.to_bytes(DHT_LPORT, 2, 'big')

cpdef bytes compact_addr(str exp_addr, unsigned short port):
    return inet_aton(exp_addr).bytes() + port.to_bytes(2, 'big')

cpdef object uncompact_port(bytes cp):
    '''
    Unpacks a 6-byte peer info bytes into a 4 byte compact addr and int port.
    '''
    return cp[:4], cp[4] * 256 + cp[5]

cpdef object uncompact_addr(bytes cp):
    '''
    Unpacks a 6-byte peer info bytes into a four-byte address and int port.
    '''
    return <bytes>inet_ntoa(cp[:4]), cp[4]*256 + cp[5]

cpdef object uncompact_nodeinfo(bytes cp):
    '''
    Unpacks a 26-byte note information bytes into a 20-byte node id,
    dot notation ip address and int port.
    '''
    return cp[:20], uncompact_addr(cp[20:26])

cpdef long d_kad(bytes a, bytes b):
    return 256*(a[0] ^ b[0]) + (a[1] ^ b[1])
