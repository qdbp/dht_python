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

cpdef str format_uptime(unsigned int s):
    cdef:
        int m, h, d, y

    if 3600 <= s < (24 * 3600):
        h = s // 3600
        m = (s // 60) % 60
        return '{:>02d} h {:>02d} m'.format(h, m)

    elif 60 <= s < 3600:
        m = s // 60
        s = s % 60
        return '{:>02d} m {:>02d} s'.format(m, s)

    if (24 * 3600) <= s < (24 * 3600 * 365):
        d = s // (24 * 3600)
        h = (s // 3600) % 24
        return '{:>02d} d {:>02d} h'.format(d, h)

    elif 0 <= s < 60:
        return '    {:>02d} s'.format(s)

    else:
        y = s // (365 * 24 * 3600)
        d = (s // (3600 * 24)) % 365
        return '{:>02d} y {:>02d} d'.format(y, d)

# cdef class DHTCounter:
# 
#     cdef public:
# 
#         uint64_t rx_msg
#         uint64_t rx_msg_ping
#         uint64_t rx_msg_ping_r
#         uint64_t rx_msg_gp
#         uint64_t rx_msg_gp_r
#         uint64_t rx_msg_fp
#         uint64_t rx_msg_fp_r
#         uint64_t rx_msg_ap
#         uint64_t rx_msg_ap_r
#         uint64_t rx_msg_other
#         uint64_t rx_msg_other_r
# 
#         uint64_t tx_msg
#         uint64_t tx_msg_ping
#         uint64_t tx_msg_ping_r
#         uint64_t tx_msg_gp
#         uint64_t tx_msg_gp_r
#         uint64_t tx_msg_fp
#         uint64_t tx_msg_fp_r
#         uint64_t tx_msg_ap
#         uint64_t tx_msg_ap_r
#         uint64_t tx_msg_other
#         uint64_t tx_msg_other_r
