'''
Hooks to bring in pxd-defined c-level functions and objects into pure
python scope for testing.
'''

from bdecode_st cimport parsed_msg, krpc_bdecode, print_parsed_msg, g_trace
from bdecode_st cimport bd_status, bd_status_names

from util cimport LRUCache
from util cimport LRU_EMTPY

cpdef show_bdecode(bytes b):

    cdef parsed_msg output
    cdef bd_status status = krpc_bdecode(b, &output)

    if status == bd_status.NO_ERROR:
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

    cpdef pophead(self):
        return self._lru.pophead()

    cpdef poptail(self):
        return self._lru.poptail()

    def __len__(self):
        return len(self._lru)
