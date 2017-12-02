from libc.stdint cimport uint64_t as u64, uint8_t as u8


cdef:
    object LRU_EMTPY

cdef class LRULink:
    cdef public:
        object val
        object key
        LRULink nx
        LRULink pr

# cdef struct LRULink:
#     LRULink *pr
#     LRULink *nx
#     void *key
#     void *val

cdef class LRUCache:
    cdef public:
        u64 hits
        u64 misses
        u64 maxlen

        u64 len
        dict d

        LRULink head
        LRULink tail
        
        void traverse(self)
        void insert(self, object, object)
        object get(self, object)
        object pophead(self)
        object poptail(self)
        tuple stats(self)
        void reset_stats(self)

cdef u64 sim_kad_apx(u8 *, u8 *)

cdef str format_uptime(u64)
