# cython: boundscheck=False

from libc.stdlib cimport atoi
from libc.string cimport const_char

cimport cython

# from libc.stdint cimport uint8_t as u8
# from libc.stdint cimport uint64_t as u64


cdef:

    NUMS = [str(x).encode()[0] for x in range(10)]
    R_NUMS = {ord(str(n).encode()): n for n in range(10)}
    STRLEN = {n : str(n).encode() for n in range(1024)}
    unsigned char COL_ORD = ord(b':')

class BdecodeError(Exception):
    pass

class BencodeError(Exception):
    pass

cdef inline int _bdecode_atoi(unsigned char* buf, unsigned int *ix):
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

cdef object _bdecode_d(unsigned char* data, unsigned int *ix):
    cdef:
        dict out = {}
        object k

    ix[0] += 1
    k = _bdecode(data, ix)
    while k is not None:
        out[k] = _bdecode(data, ix)
        k = _bdecode(data, ix)
    return out

cdef object _bdecode_s(unsigned char* data, unsigned int *ix):
    cdef:
        int c_ix, slen, start

    slen = _bdecode_atoi(data, ix)
    start = ix[0]
    ix[0] += slen

    return <bytes> data[start:start + slen]

cdef object _bdecode_e(unsigned char* data, unsigned int *ix):
    ix[0] += 1
    return None

cdef object _bdecode_i(unsigned char* data, unsigned int *ix):
    ix[0] += 1
    return _bdecode_atoi(data, ix)

cdef object _bdecode_l(unsigned char* data, unsigned int *ix):
    cdef:
        list out = []
        object ret

    ix[0] += 1
    ret = _bdecode(data, ix)
    while ret is not None:
        out.append(ret)
        ret = _bdecode(data, ix)
    return out

cdef object _bdecode_err(unsigned char* data, unsigned int *ix):
    raise BdecodeError()

cdef object (*BDEC_TAB[256])(unsigned char*, unsigned int*)

for i in range(256):
    BDEC_TAB[i] = &_bdecode_err

BDEC_TAB[ord(b'd')] = &_bdecode_d
BDEC_TAB[ord(b'e')] = &_bdecode_e
BDEC_TAB[ord(b'i')] = &_bdecode_i
BDEC_TAB[ord(b'l')] = &_bdecode_l

for i in NUMS:
    BDEC_TAB[i] = &_bdecode_s

cdef object _bdecode(unsigned char* data, unsigned int *ix):
    return BDEC_TAB[data[ix[0]]](data, ix)

cpdef object bdecode(bytes data):
    cdef:
        unsigned int ix = 0
    return _bdecode(data, &ix)

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

cpdef bytes mk_ping_ap_reply(bytes sid, bytes tok):

    cdef bytes out

    return (
        b'd1:rd2:id20:' + sid + b'e1:t' + str(len(tok)).encode('ascii') + 
        b':' + tok + b'1:y1:re'
    )

cpdef bytes mk_gp_fp_reply(bytes sid, bytes tok, int gp):
    '''
    Make a reply with an empty list of nodes.

    Can be used to DDoS, I guess, if you put someone's node here.
    '''
    cdef bytes out

    return (
        b'd1:rd2:id20:' + sid +
        b'5:nodes0:' +
        # b'\xb3\x97\xd6\x06\xa3s{\xa5Q\x03@>\x14P' + 
        # b'\xd4L\xc8\xd6\x99>P\x1f\xc3\xe6A\x9b' +
        (b'5:token1:\x88' if gp else b'') + b'e' +
        b'1:t' + str(len(tok)).encode('ascii') + b':' +
        tok + b'1:y1:re'
    )
