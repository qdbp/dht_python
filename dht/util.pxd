from libc.stdint cimport uint64_t

cdef class LRULink:
    cdef public:
        object val
        object key
        LRULink nx
        LRULink pr

cdef class LRUCache:
    cdef:
        uint64_t hits
        uint64_t misses
        uint64_t maxlen

        uint64_t _len
        dict _d

        LRULink head
        LRULink tail
        
    cdef void traverse(self)
    cdef void insert(self, object, object)
    cdef object get(self, object)
    cdef tuple stats(self)
    cdef void reset_stats(self)
