# cython: profile=True
# cython: boundscheck=False
# cython: wraparound=False

from libc.stdlib cimport atoi
from libc.string cimport memcmp, memset

cimport cython

from libc.stdint cimport uint8_t as u8, uint64_t as u64, uint16_t as u16, uint32_t as u32
from libc.string cimport memcpy
# from libc.stdint cimport uint64_t as u64

DEF IH_LEN = 20
DEF PEERINFO_LEN = 6
DEF NODEINFO_LEN = IH_LEN + PEERINFO_LEN

DEF BD_MAXLEN = 1024

cdef:
    STRLEN = {n : str(n).encode() for n in range(1024)}
    u8 COL_ORD = ord(b':')

    struct parsed_msg:
        bint fail
        # null-terminated token
        u8 tok[32]
        # token length, for convenience
        u64 tok_len
        # self explanatory
        u8 nid[IH_LEN]
        u8 ih[IH_LEN]
        u8 target[IH_LEN]
        # method used, one of the METHOD_ constants
        u64 method
        # nodes, not all will be set
        u8 nodes[NODEINFO_LEN * 8]
        # number of nodes set
        u64 num_nodes
        # gp token
        u8 token[32]
        # token length
        u64 token_len
        # peers, not all will be set
        u8 peers[PEERINFO_LEN * 8]
        # number of peers set
        u64 peers_len
        # if implied port is set
        bint implied_port

class BdecodeError(Exception):
    pass

class BencodeError(Exception):
    pass

@cython.profile(False)
cdef inline int bdecode_atoi(u8 * buf, u64 *ix, u64 maxlen):
    '''
    Decode strictly nonnegative, colon-terminated decimal integers. Fast.

    Is stateful: xdvances the buffer index in-place. Advances the index
    an extra position on returning, thus consuming the termination symbol.
    '''

    cdef int out = 0
    cdef int sign = 1

    if ix[0] < maxlen and buf[ix[0]] == 45:
        sign = -1
        ix[0] += 1

    # ord(decimal_digit) = decimal_digit + 48
    while ix[0] < maxlen and 48 <= buf[ix[0]] < 58:
        out = 10 * out + buf[ix[0]] - 48
        ix[0] += 1

    # consume the position of the b':' or b'e'
    ix[0] += 1

    return out * sign

@cython.profile(False)
cdef dict bdecode_d(u8 * data, u64 *ix, u64 maxlen):
    # print('bdecode_d with data at', ix[0], data[ix[0]:])
    cdef:
        dict out = {}
        object k

    ix[0] += 1
    while True:
        k = bdecode_dispatch(data, ix, maxlen)
        if k is None:
            break
        else:
            out[k] = bdecode_dispatch(data, ix, maxlen)
    # print('returning ', out)
    return out

@cython.profile(False)
cdef inline bytes bdecode_s(u8 * data, u64 *ix, u64 maxlen):
    cdef:
        int slen, start, out

    slen = bdecode_atoi(data, ix, maxlen)
    start = ix[0]
    ix[0] += slen

    if maxlen >= start + slen:
        return data[start:start + slen] 
    else:
        return None

@cython.profile(False)
cdef inline int bdecode_i(u8 * data, u64 *ix, u64 maxlen):
    # print('bdecode_i with data at', ix[0], data[ix[0]:])
    ix[0] += 1
    return bdecode_atoi(data, ix, maxlen)

@cython.profile(False)
cdef list bdecode_l(u8 * data, u64 *ix, u64 maxlen):
    # print('bdecode_l with data at', ix[0], data[ix[0]:])
    cdef:
        list out = []
        object ret

    ix[0] += 1
    while True:
        ret = bdecode_dispatch(data, ix, maxlen)
        if ret is None:
            break
        else:
            out.append(ret)
    return out

@cython.profile(False)
cdef inline object bdecode_dispatch(u8 * data, u64 *ix, u64 maxlen):
    # print('bdecode_dispatch with data at', ix[0], data[ix[0]:])
    if ix[0] >= maxlen:
        return None
        # raise BdecodeError()
    elif 0x30 <= data[ix[0]] < 0x40:
        # print('s branch')
        return <object> bdecode_s(data, ix, maxlen)
    elif data[ix[0]] == 100:  # b'd'
        # print('d branch')
        return <object> bdecode_d(data, ix, maxlen)
    elif data[ix[0]] == 108:  # b'l'
        # print('l branch')
        return <object> bdecode_l(data, ix, maxlen)
    elif data[ix[0]] == 105:  # b'i'
        # print('i branch')
        return <object> bdecode_i(data, ix, maxlen)
    elif data[ix[0]] == 101:  # b'e'
        # print('e branch')
        ix[0] += 1

    return None
    #     # print('e branch')
    #     ix[0] += 1
    #     return None
    # else:
    #     return None
    #     # print('err branch')

cdef object bdecode(bytes data):
    cdef u64 ix = 0
    cdef u64 ld = len(data)
    cdef u64 maxlen = ld if ld <= BD_MAXLEN else BD_MAXLEN
    cdef u8 buf[BD_MAXLEN]
    memcpy_bytes(buf, data, maxlen)
    return bdecode_dispatch(buf, &ix, maxlen)

cpdef bytes bencode(object data):
    if isinstance(data, bytes):
        return STRLEN[len(data)] + b':' + data
    elif isinstance(data, dict):
        return b'd' + b''.join([bencode(k) + bencode(v) for k, v in sorted(data.items())]) + b'e'
    elif isinstance(data, str):
        e_data = data.encode()
        return str(len(e_data)).encode() + b':' + e_data
    elif isinstance(data, int):
        return b'i' + str(data).encode() + b'e'
    elif isinstance(data, list):
        return b'l' + b''.join([bencode(x) for x in data]) + b'e'
    else:
        raise BencodeError()

@cython.profile(False)
cdef inline void memcpy_bytes(u8 *target, u8 *source, u64 up_to):
    memcpy(target, source, up_to)
