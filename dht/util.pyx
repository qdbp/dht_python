# cython: profile=True
from hashlib import sha1
import re
from socket import inet_ntoa, inet_aton




cpdef bytes compact_node(bytes node):
    '''
    Returns the 4-byte prefix of the node followed by the unchanged
    six-byte compact address info.
    '''
    return node[:4] + node[20:26]


cpdef bytes compact_addr(str exp_addr, unsigned short port):
    return inet_aton(exp_addr) + port.to_bytes(2, 'big')


cpdef object uncompact_addr(bytes cp):
    return inet_ntoa(cp[:4]).encode(), cp[4]*256 + cp[5]


cpdef object uncompact_nodeinfo(bytes cp):
    return cp[:20], uncompact_addr(cp[20:26])


cpdef object uncompact_prefix(bytes cp):
    return cp[:4], uncompact_addr(cp[4:10])


cdef class Verdict:

    cdef public:
        bytes peers
        bytes response
        bytes packed_nodes
        bytes info_hash
        int gp_flag


NODES_RE = re.compile(b'5:nodes').search
QUERY_RE = re.compile(b'1:y1:q').search
VALUES_RE = re.compile(b'6:values').search
QUERY_GP_FN_RE = re.compile(b'1:q9:(?:get_peers|find_node)').search

cpdef Verdict fast_dissect(bytes msg):
    pass



cpdef long d_kad(bytes a, bytes b):
    return 256*(a[0] ^ b[0]) + (a[1] ^ b[1])


cpdef bytes get_sid(bytes nid, bytes salt):
    return sha1(nid + salt)
