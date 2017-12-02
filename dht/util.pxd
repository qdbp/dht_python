from libc.stdint cimport uint64_t as u64, uint8_t as u8

cdef class LRULink:
    cdef public:
        object val
        object key
        LRULink nx
        LRULink pr

cdef class LRUCache:
    cdef:
        u64 hits
        u64 misses
        u64 maxlen

        u64 _len
        dict _d

        LRULink head
        LRULink tail
        
    cdef void traverse(self)
    cdef void insert(self, object, object)
    cdef object get(self, object)
    cdef tuple stats(self)
    cdef void reset_stats(self)

cdef u64 sim_kad_apx(u8 *, u8 *)

cdef str format_uptime(u64)
