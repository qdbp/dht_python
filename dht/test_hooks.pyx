'''
Hooks to bring in pxd-defined c-level functions and objects into pure
python scope for testing.
'''

include "dht_h.pxi"

from bdecode_st cimport parsed_msg, krpc_bdecode, print_parsed_msg, g_trace
from bdecode_st cimport bd_status_names
from stat cimport ST

from util cimport LRUCache
from util cimport LRU_EMTPY, LRU_NONE

cpdef get_lru_none():
    return LRU_NONE

cpdef get_lru_empty():
    return LRU_EMTPY

cpdef show_bdecode(bytes b):

    cdef parsed_msg output
    cdef u64 status = krpc_bdecode(b, &output)

    if status == ST.bd_a_no_error:
        print_parsed_msg(&output)

    return bd_status_names[status]

cpdef print_trace():
    print('\n'.join(g_trace))


cdef class LRUCacheDummy:

    cdef public:
        LRUCache _lru

    def __cinit__(self, k):
        self._lru = LRUCache(k)

    cpdef traverse(self):
        return self._lru.traverse()

    cpdef insert(self, key, value):
        return self._lru.insert(key, value)

    cpdef get(self, key):
        return self._lru.get(key)

    cpdef pop(self, key):
        return self._lru.pop(key)

    cpdef pophead(self):
        return self._lru.pophead()

    cpdef poptail(self):
        return self._lru.poptail()

    def __len__(self):
        return len(self._lru)
