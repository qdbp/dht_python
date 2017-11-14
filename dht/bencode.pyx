# cython: boundscheck=False

from libc.stdlib cimport atoi
from libc.string cimport const_char


NUMS = [str(x).encode()[0] for x in range(10)]

R_NUMS = {ord(str(n).encode()): n for n in range(10)}

STRLEN = {n : str(n).encode() for n in range(1024)}

class BdecodeError(Exception):
    pass

class BencodeError(Exception):
    pass

cdef unsigned int _bdecode_diglen(int x):
    cdef:
        unsigned int out
    
    if 0 <= x < 10:
        return 1

    if x < 0:
        out = 1
        x = -x
    else:
        out = 0

    while x > 0:
        out += 1
        x //= 10

    return out

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

cdef object _bdecode_d(bytes data, int *ix):
    cdef:
        dict out = {}
        object k

    ix[0] += 1
    k = _bdecode(data, ix)
    while k is not None:
        out[k] = _bdecode(data, ix)
        k = _bdecode(data, ix)
    return out

cdef object _bdecode_s(bytes data, int *ix):
    cdef:
        int c_ix, l, start

    l = atoi(data[ix[0]:])
    start = ix[0] + _bdecode_diglen(l) + 1

    ix[0] = start + l

    return data[start:ix[0]]

cdef object _bdecode_e(bytes data, int *ix):
    ix[0] += 1
    return None

cdef object _bdecode_i(bytes data, int *ix):
    cdef:
        object out

    out = atoi(data[ix[0] + 1:])
    ix[0] += _bdecode_diglen(out) + 2

    return out

cdef object _bdecode_l(bytes data, int *ix):
    cdef:
        list out = []
        object ret

    ix[0] += 1
    ret = _bdecode(data, ix)
    while ret is not None:
        out.append(ret)
        ret = _bdecode(data, ix)
    return out

cdef object _bdecode_err(bytes data, int *ix):
    raise BdecodeError()

cdef object (*BDEC_TAB[256])(bytes, int*)

for i in range(256):
    BDEC_TAB[i] = &_bdecode_err

BDEC_TAB[ord(b'd')] = &_bdecode_d
BDEC_TAB[ord(b'e')] = &_bdecode_e
BDEC_TAB[ord(b'i')] = &_bdecode_i
BDEC_TAB[ord(b'l')] = &_bdecode_l

for i in NUMS:
    BDEC_TAB[i] = &_bdecode_s

cdef object _bdecode(bytes data, int *ix):
    return BDEC_TAB[data[ix[0]]](data, ix)


cpdef int catoi(bytes bs):
    return atoi(bs)


cpdef object bdecode(bytes data):
    cdef:
        int ix = 0
    return _bdecode(data, &ix)
