# cython: profile=True
# cython: wraparound=False

from libc.stdlib cimport atoi
from libc.string cimport memcmp, memset

cimport cython

from libc.stdint cimport uint8_t as u8, uint64_t as u64, uint16_t as u16, uint32_t as u32
# from libc.stdint cimport uint64_t as u64

cdef:
    STRLEN = {n : str(n).encode() for n in range(1024)}
    unsigned char COL_ORD = ord(b':')

    struct bdec_res:
        bint fail
        unsigned char tok[32]
        u64 tok_len
        unsigned char nid[20]
        unsigned char ih[20]
        u64 method
        unsigned char nodes[26 * 8]
        u64 nodes_len
        unsigned char peers[6 * 8]
        u64 peers_len
        unsigned char token[32]
        bint implied_port

class BdecodeError(Exception):
    pass

class BencodeError(Exception):
    pass

cdef inline int bdecode_atoi(bytes buf, u64 *ix):
    '''
    Decode strictly nonnegative, colon-terminated decimal integers. Fast.

    Is stateful: xdvances the buffer index in-place. Advances the index
    an extra position on returning, thus consuming the termination symbol.
    '''

    cdef int out = 0
    cdef int sign = 1

    if buf[ix[0]] == 45:
        sign = -1
        ix[0] += 1

    # ord(decimal_digit) = decimal_digit + 48
    while 48 <= buf[ix[0]] < 58:
        out = 10 * out + buf[ix[0]] - 48
        ix[0] += 1

    # consume the position of the b':' or b'e'
    ix[0] += 1

    return out * sign

cdef dict bdecode_d(bytes data, u64 *ix):
    # print('bdecode_d with data at', ix[0], data[ix[0]:])
    cdef:
        dict out = {}
        object k

    ix[0] += 1
    while True:
        k = bdecode_dispatch(data, ix)
        if k is None:
            break
        else:
            out[k] = bdecode_dispatch(data, ix)
    return out

cdef inline bytes bdecode_s(bytes data, u64 *ix):
    # print('bdecode_s with data at', ix[0], data[ix[0]:])
    cdef:
        int slen, start, out

    # out = bdec_s_heur(data, ix)
    # if not out:
    slen = bdecode_atoi(data, ix)
    start = ix[0]
    ix[0] += slen

    return <bytes> data[start:start + slen] 

cdef inline object bdecode_i(bytes data, u64 *ix):
    # print('bdecode_i with data at', ix[0], data[ix[0]:])
    ix[0] += 1
    return bdecode_atoi(data, ix)

cdef object bdecode_l(bytes data, u64 *ix):
    # print('bdecode_l with data at', ix[0], data[ix[0]:])
    cdef:
        list out = []
        object ret

    ix[0] += 1
    while True:
        ret = bdecode_dispatch(data, ix)
        if ret is None:
            break
        else:
            out.append(ret)
    return out

cdef object bdecode(bytes data):
    cdef u64 ix = 0
    return bdecode_dispatch(data, &ix)

cdef inline object bdecode_dispatch(bytes data, u64 *ix):
    # print('bdecode_dispatch with data at', ix[0], data[ix[0]:])
    if 0x30 <= data[ix[0]] < 0x40:
        # print('s branch')
        return <object> bdecode_s(data, ix)
    elif data[ix[0]] == 100:  # b'd'
        # print('d branch')
        return <object> bdecode_d(data, ix)
    elif data[ix[0]] == 108:  # b'l'
        # print('l branch')
        return <object> bdecode_l(data, ix)
    elif data[ix[0]] == 105:  # b'i'
        # print('i branch')
        return <object> bdecode_i(data, ix)
    elif data[ix[0]] == 101:  # b'e'
        # print('e branch')
        ix[0] += 1
        return None
    else:
        # print('err branch')
        raise BdecodeError()

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
