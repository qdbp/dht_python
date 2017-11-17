# cython: profile=True
from hashlib import sha1
import re
from socket import inet_ntoa, inet_aton

from libc.stdint cimport uint64_t, uint8_t
from libc.stdlib cimport atoi, rand
from libc.math cimport fmax, fmin

import numpy as np
from numpy.random import bytes as rbytes
cimport numpy as np

cimport cython

DEF CONTACTS_PER_SLOT = 5
DEF IH_LEN = 20
DEF NODEINFO_LEN = 26
DEF MAX_QUAL = 6
DEF MIN_QUAL = 0  # guarantees eviction
# DEF NODE_SUFFIX = b'X\xf3Q\xca\xf1=\xd42\xae\x86j\xa9\xd6\x0c=\xe8D\x99'

cdef unsigned char nsuf[18]
nsuf[:] = rbytes(18)[0:18]


@cython.wraparound(False)
@cython.wraparound(True)
cpdef bytes mk_sid(const unsigned char *nid):
    cdef int ix
    cdef unsigned char buf[20]
    cdef unsigned char *nsuf =\
        b'\x00\x00X\xf3Q\xca\xf1=\xd42\xae\x86j\xa9\xd6\x0c=\xe8D\x99'

    for ix in range(0, 20):
        buf[ix] = nid[ix] ^ nsuf[ix]

    return bytes(buf[0:20])

cpdef bytes compact_ip(bytes ip_addr):
    '''
    A reduced for if inet_aton that accepts bytes instead of str.
    '''
    cdef:
        unsigned int ix = 0
        unsigned int jx = 0
        unsigned int bx = 0
        unsigned int tx = 0
        unsigned int lb = len(ip_addr)
        unsigned char buf[4]

    for bx in range(lb):
        if ip_addr[bx] == 0x2e:
            tx += 1
            if tx > 3:
                return None
        elif 0x30 <= ip_addr[bx] < 0x40:
            buf[tx] = buf[tx] * 10 + (ip_addr[bx] - 0x30)
        else:
            return None

    return bytes(buf[0:4])

cpdef bytes compact_addr(bytes exp_addr, unsigned short port):
    return compact_ip(exp_addr) + port.to_bytes(2, 'big')

@cython.wraparound(False)
cpdef object uncompact_peer_partial(unsigned char *cp):
    '''
    Unpacks a 6-byte peer info bytes into a 4 byte compact addr and int port.
    '''
    return cp[:4], cp[4] * 256 + cp[5]

@cython.wraparound(False)
cpdef object uncompact_peer_full(unsigned char *cp):
    '''
    Unpacks a 6-byte peer info bytes into a four-byte address and int port.
    '''
    return inet_ntoa(cp[:4]).encode('ascii'), cp[4] * 256 + cp[5]

@cython.wraparound(False)
cpdef object uncompact_nodeinfo(unsigned char *cp):
    '''
    Unpacks a 26-byte note information bytes into a 20-byte node id,
    dot notation ip address and int port.
    '''
    return cp[:IH_LEN], uncompact_peer_full(cp[IH_LEN:NODEINFO_LEN])

cpdef long d_kad(bytes a, bytes b):
    return 256*(a[0] ^ b[0]) + (a[1] ^ b[1])

cpdef str format_uptime(unsigned int s):
    cdef:
        int m, h, d, y

    if 3600 <= s < (24 * 3600):
        h = s // 3600
        m = (s // 60) % 60
        return '{:>2d} h {:>2d} m'.format(h, m)

    elif 60 <= s < 3600:
        m = s // 60
        s = s % 60
        return '{:>2d} m {:>2d} s'.format(m, s)

    if (24 * 3600) <= s < (24 * 3600 * 365):
        d = s // (24 * 3600)
        h = (s // 3600) % 24
        return '{:>2d} d {:>2d} h'.format(d, h)

    elif 0 <= s < 60:
        return '    {:>2d} s'.format(s)

    else:
        y = s // (365 * 24 * 3600)
        d = (s // (3600 * 24)) % 365
        return '{:>2d} y {:>2d} d'.format(y, d)

cpdef np.ndarray new_sid_addr_table():
    return np.zeros((256, 256, CONTACTS_PER_SLOT, NODEINFO_LEN), dtype=np.uint8)

cpdef np.ndarray new_rt_qual_table():
    return np.zeros((256, 256, CONTACTS_PER_SLOT), dtype=np.uint8)

@cython.boundscheck(False)
@cython.wraparound(False)
cdef unsigned int is_row_empty(np.ndarray [uint8_t, ndim=1] row):

    cdef int ix

    for ix in range(IH_LEN):
        if row[ix]:
            return 0

    return 1

@cython.boundscheck(False)
@cython.wraparound(False)
cdef unsigned int is_row_equal(
        np.ndarray[uint8_t, ndim=1] row,
        const unsigned char *target,
        unsigned int up_to):

    cdef unsigned int ix

    for ix in range(up_to):
        if (row[ix] ^ target[ix]):
            return 0

    return 1

@cython.wraparound(False)
@cython.boundscheck(False)
cpdef bytes get_random_node(np.ndarray [uint8_t, ndim=4] t):

    cdef:
        unsigned int start_ix = rand() % (256 * 256 * 5)
        unsigned int ix, ax, bx, cx
        np.ndarray[uint8_t, ndim=1] row

    for ix in range(start_ix, 256 * 256 * 5):
        cx = ix % 5
        bx = (ix // 256) % 256
        ax = ix // (256 * 256)
        row = t[ax][bx][cx]
        if not is_row_empty(row):
            return bytes(row)

    for ix in range(0, start_ix):
        cx = ix % 5
        bx = (ix // 256) % 256
        ax = ix // (256 * 256)
        row = t[ax][bx][cx]
        if not is_row_empty(row):
            return bytes(row)

    return None

@cython.boundscheck(False)
@cython.wraparound(False)
cpdef bytes get_neighbor_nid(
        np.ndarray [uint8_t, ndim=4] narr, const unsigned char *target):
    '''
    Returns a nid from the array of nids `narr` whose first two bytes
    match the target.
    '''

    cdef:
        unsigned int start_ix
        unsigned int ix
        unsigned char ax, bx
        np.ndarray [uint8_t, ndim=1] row

    start_ix = rand() % CONTACTS_PER_SLOT
    ax = target[0]
    bx = target[1]


    for ix in range(start_ix, CONTACTS_PER_SLOT):
        row = narr[ax][bx][ix]
        if not is_row_empty(row):
            return bytes(row)

    for ix in range(0, start_ix):
        row = narr[ax][bx][ix]
        if not is_row_empty(row):
            return bytes(row)

    return None

@cython.boundscheck(False)
@cython.wraparound(False)
cpdef void insert_nid(
        np.ndarray [uint8_t, ndim=4] narr,
        unsigned char *new_nid,
        int cx=-1):

    cdef:
        unsigned int ix
        unsigned char ax, bx
        np.ndarray [uint8_t, ndim=1] row

    ax = new_nid[0]
    bx = new_nid[1]

    cx = (rand() % CONTACTS_PER_SLOT) if cx < 0 else cx

    row = narr[ax][bx][cx]

    for ix in range(IH_LEN):
        row[ix] = new_nid[ix]

cdef unsigned int do_evict(unsigned int qual):
    '''
    Evicts qual x with prob 1 / (2 ^ x).
    '''

    return (rand() & ((1 << qual) - 1)) == 0

@cython.boundscheck(False)
@cython.wraparound(False)
cpdef unsigned int random_replace_contact(
        np.ndarray[uint8_t, ndim=4] t,
        np.ndarray[uint8_t, ndim=3] q, 
        const unsigned char *new_contact):
    '''
    Possible randomly replaces a contact in the table `t` with the
    `new_contact`.

    An old contact has a chance to be evicted inversely proportional to
    its quality given by table `q`.

    If no contact is evicted, the new_contact is simply ignored.
    '''

    cdef:
        unsigned int ax, bx, cx, jx
        np.ndarray[uint8_t, ndim=1] row

    ax = new_contact[0]
    bx = new_contact[1]
    cx = rand() % CONTACTS_PER_SLOT

    if do_evict(q[ax][bx][cx]):
        row = t[ax][bx][cx]
        for jx in range(NODEINFO_LEN):
            row[jx] = new_contact[jx]
        return 1
    return 0

@cython.boundscheck(False)
@cython.wraparound(False)
cpdef unsigned int adj_quality(
        np.ndarray[uint8_t, ndim=4] t,
        np.ndarray[uint8_t, ndim=3] q,
        const unsigned char *target_nid,
        int delta):

    cdef:
        unsigned int ax, bx, ix
        np.ndarray [uint8_t, ndim=1] row

    ax = target_nid[0]
    bx = target_nid[1]

    for ix in range(CONTACTS_PER_SLOT):
        row = t[ax][bx][ix]
        if is_row_equal(row, target_nid, IH_LEN):
            q[ax][bx][ix] =\
                fmax(fmin(q[ax][bx][ix] + delta, MAX_QUAL), MIN_QUAL)
            return 1

    # failed to find a match
    return 0

cpdef bytes bencode_tok(bytes tok):

    cdef int lt = len(tok)
    cdef bytes slt = str(lt).encode('ascii')

    return slt + b':' + tok

cdef unsigned int KAD_TAB[256]
KAD_TAB[:] = (
    [8] + [7] + [6] * 2 + [5] * 4 + [4] * 8 + [3] * 16 + [2] * 32 + [1] * 64 +
    [0] * 128 
)[:]

cpdef unsigned int lkad(bytes x, bytes y):
    '''
    Logaritmic approximation to the kademlia distance: the index of the
    first differing bit.
    '''
    cdef:
        unsigned int out = 0
        unsigned int ix = 0
    
    for ix in range(IH_LEN):
        dist = KAD_TAB[x[ix] ^ y[ix]]
        out += dist
        if dist:
            break

    return out

@cython.wraparound(False)
cpdef unsigned int validate_ip(unsigned char *ip):

    cdef:
        unsigned char a = ip[0]
        unsigned char b = ip[1]
        unsigned char c = ip[2]
        unsigned char d = ip[3]

    # taken from https://www.iana.org/assignments/iana-ipv4-special-registry/
    if (
            ((a & 0xf0) == 240) or # 240.0.0.0/4
            (a == 0) or
            (a == 10) or
            (a == 127) or
            (a == 100 and (b & 0xc0) == 64) or
            (a == 172 and (b & 0xf0) == 16) or
            (a == 198 and (b &0xfe == 18)) or
            (a == 169 and b == 254) or
            (a == 192 and b == 168) or
            (a == 192 and b == 0   and c == 0) or
            (a == 192 and b == 0   and c == 2) or
            (a == 192 and b == 31  and c == 196) or
            (a == 192 and b == 51  and c == 100) or
            (a == 192 and b == 52  and c == 193) or
            (a == 192 and b == 175 and c == 48) or
            (a == 198 and b == 51  and c == 100) or
            (a == 203 and b == 0   and c == 113) or
            (a == 255 and b == 255 and c == 255 and d == 255)):

        return 0

    return 1
