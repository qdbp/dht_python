from libc.stdint cimport uint64_t as u64

cdef dict bdecode_d(bytes, u64 *)
cdef object bdecode(bytes)
