from libc.stdint cimport uint8_t as u8, uint64_t as u64

# cdef dict bdecode_d(unsigned char *, u64 *, u64 maxlen)
cdef object bdecode(bytes)
