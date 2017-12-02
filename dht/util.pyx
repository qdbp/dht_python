# cython: profile=True
from libc.stdint cimport uint64_t as u64, uint8_t as u8
cimport cython

include "dht_h.pxi"


@cython.freelist(16)
cdef class LRULink:
    pass

cdef class LRUCache:
    '''
    A generic dict-cache with recency-based eviction.
    '''

    def __cinit__(self, u64 maxlen):
        # need maxlen to be at least two for the code below to run correctly
        self.maxlen = max(maxlen, 2)
        self.hits = 0
        self.misses = 0
        self._len = 0
        self._d = {}

    cdef void traverse(self):
        print('len is', self._len)
        print('dict is', self._d)
        cdef LRULink cur_node = self.head
        while cur_node:
            print(cur_node.key, cur_node.val)
            cur_node = cur_node.nx

    cdef void insert(self, object key, object val):
        cdef:
            LRULink this_link

        # if we have the link in the dict, we move it to the front...
        if key in self._d:
            this_link = self._d[key]
            # update its value, knowing the key stays the same...
            this_link.val = val

            # if it's a middle link...
            if this_link.pr and this_link.nx:
                this_link.pr.nx = this_link.nx
                this_link.nx.pr = this_link.pr

            # if it's a proper tail
            elif this_link.pr and not this_link.nx:
                this_link.pr.nx = None
                self.tail = this_link.pr

            # else we do nothing, since it's a head already and all we needed
            # to do was to update the value.
            else:
                return

            # if we were not the head, reattach as the head
            this_link.nx = self.head
            this_link.pr = None
            self.head.pr = this_link
            self.head = this_link

        # if we don't have the key...
        else:
            # if there's room, we mint a new link
            if self._len < self.maxlen:
                this_link = LRULink()
                this_link.key = key
                this_link.val = val

                self._len += 1
                self._d[key] = this_link

                # if it's the first link, create the head
                if self.head is None:
                    self.head = this_link
                    self.tail = this_link
                    self._d[key] = self.head
                    return
                # otherwise attach the new link as the new head
                else:
                    this_link.nx = self.head
                    self.head.pr = this_link
                    self.head = this_link
            # if the cache is full, we cannibalize the tail link by...
            else:
                this_link = self.tail
                # deleting the reference to the old key from the dict...
                del self._d[this_link.key]
                # updating the key and value...
                this_link.key = key
                this_link.val = val
                # insert it into the dict
                self._d[key] = this_link
                # making the previous link the tail...
                self.tail = self.tail.pr
                self.tail.nx = None
                # and making this link the head
                this_link.nx = self.head
                this_link.pr = None
                self.head.pr = this_link
                self.head = this_link

    cdef object get(self, object key):
        if key in self._d:
            val = self._d[key].val
            self.insert(key, val)
            self.hits += 1
            return val
        else:
            self.misses += 1
            return None

    cdef tuple stats(self):
        return (
            self.hits,
            self.misses,
            (self.hits + 1.) / (self.hits + self.misses + 2.),
        )

    cdef void reset_stats(self):
        self.hits = 0
        self.misses = 0


cdef u64 tab_kad[256]

tab_kad = [8] + [7] + [6] * 2 + [5] * 4 + [4] * 8 + [3] * 16 + [2] * 32 + [1] * 64 + [0] * 128

@cython.boundscheck(False)
@cython.wraparound(False)
cdef u64 sim_kad_apx(u8 *x, u8 *y):
    '''
    MEM-UNSAFE [x[0:IH_LEN], y[0:IH_LEN]]

    Approximate kademlia similarity, given by index of first bit at which the
    inputs differ, or 160 if they do not differ.

    Range [0, 160]
    '''
    
    cdef u64 out = 0
    cdef u8 byte_sim = 0
    cdef u64 ix = 0

    for ix in range(IH_LEN):
        byte_sim = tab_kad[x[ix] ^ y[ix]]
        out += byte_sim
        if byte_sim < 8:
            break

    return out

cdef str format_uptime(u64 s):
    '''
    Formats an elapsed time in seconds as a nice string of equal width
    for all times.
    '''
    cdef:
        int m, h, d, y

    if 3600 <= s < (24 * 3600):
        h = s // 3600
        m = (s // 60) % 60
        return '{:>2d} h {:>2d} m'.format(h, m)

    elif 60 <= s < 3600:
        m = s // 60
        s = s % 60
        return '{:>2d} m {:>2d} s'.format(m, s)

    if (24 * 3600) <= s < (24 * 3600 * 365):
        d = s // (24 * 3600)
        h = (s // 3600) % 24
        return '{:>2d} d {:>2d} h'.format(d, h)

    elif 0 <= s < 60:
        return '     {:>2d} s'.format(s)

    else:
        y = s // (365 * 24 * 3600)
        d = (s // (3600 * 24)) % 365
        return '{:>2d} y {:>2d} d'.format(y, d)

