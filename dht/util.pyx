# cython: profile=True
include "dht_h.pxi"

from cpython.mem cimport PyMem_Malloc, PyMem_Free

@cython.freelist(16)
cdef class LRULink:
    pass

cdef object LRU_EMTPY = object()
cdef object LRU_NONE = object()

cdef class LRUCache:
    '''
    THREAD-UNSAFE

    A generic dict-cache with recency-based eviction.
    '''

    def __cinit__(self, u64 maxlen):
        # need maxlen to be at least two for the code below to run correctly
        self.maxlen = max(maxlen, 2)
        self.hits = 0
        self.misses = 0
        self.len = 0
        self.d = {}

    cdef void traverse(self):
        print('len is', self.len)
        print('dict is', self.d)
        cdef LRULink cur_node = self.head
        while cur_node:
            print(cur_node.key, cur_node.val)
            cur_node = cur_node.nx

    cdef void insert(self, object key, object val):

        cdef LRULink this_link

        # if we have the link in the dict, we move it to the front...
        if key in self.d:
            this_link = self.d[key]
            # update its value, knowing the key stays the same...
            this_link.val = val

            # if it's a middle link...
            if this_link.pr and this_link.nx:
                this_link.pr.nx = this_link.nx
                this_link.nx.pr = this_link.pr

            # if it's a proper tail
            elif this_link.pr is not None and this_link.nx is None:
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
            if self.len < self.maxlen:
                this_link = LRULink()
                this_link.key = key
                this_link.val = val

                self.len += 1
                self.d[key] = this_link

                # if it's the first link, create the head
                if self.head is None:
                    self.head = this_link
                    self.tail = this_link
                    self.d[key] = self.head
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
                del self.d[this_link.key]
                # updating the key and value...
                this_link.key = key
                this_link.val = val
                # insert it into the dict
                self.d[key] = this_link
                # making the previous link the tail...
                self.tail = self.tail.pr
                self.tail.nx = None
                # and making this link the head
                this_link.nx = self.head
                this_link.pr = None
                self.head.pr = this_link
                self.head = this_link

    cdef object get(self, object key):
        if key in self.d:
            val = self.d[key].val
            self.insert(key, val)
            self.hits += 1
            return val
        else:
            self.misses += 1
            return LRU_NONE

    cdef object pop(self, object key):

        if key not in self.d:
            return LRU_NONE

        if self.len == 0:
            return LRU_EMTPY

        poplink = self.d.pop(key)
        self.len -= 1

        if self.len == 0:
            self.head = self.tail = None

        elif poplink is self.head:
            self.head.nx.pr = None
            self.head = self.head.nx

        elif poplink is self.tail:
            self.tail.pr.nx = None
            self.tail = self.tail.pr

        # the preceding cases exhaust len == 2, so we have that
        # d[key] != self.tail && d[key] != self.head
        else:
            poplink.nx.pr = poplink.pr
            poplink.pr.nx = poplink.nx

        return poplink.val

    cdef object pophead(self):
        '''
        Returns the value of the head of the LRU (the most recently seen
        object), and removes that object from the cache.

        If the LRU is empty, returns the special sentinel value LRU_EMTPY
        '''

        cdef object key

        if self.len > 0:
            # NOTE need separate reference, since 'self.head.key' as first
            # elem of return tuple produces a pointer to the key of the NEXT
            # head
            key = self.head.key
            return (key, self.pop(self.head.key))
        else:
            return LRU_EMTPY

    cdef object poptail(self):
        '''
        Returns the value of the tail of the LRU (the least recently seen
        living object), and removes that object from the cache.

        If the LRU is empty, returns the special sentinel value LRU_EMTPY
        '''

        cdef object key

        if self.len > 0:
            key = self.tail.key
            return (key, self.pop(self.tail.key))
        else:
            return LRU_EMTPY

    cdef tuple stats(self):
        return (
            self.hits,
            self.misses,
            (self.hits + 1.) / (self.hits + self.misses + 2.),
        )

    cdef void reset_stats(self):
        self.hits = 0
        self.misses = 0

    def __len__(self):
        return self.len

cdef u64 tab_kad[256]

tab_kad = [8] + [7] + [6] * 2 + [5] * 4 + [4] * 8 + [3] * 16 + [2] * 32 + [1] * 64 + [0] * 128

@cython.boundscheck(False)
@cython.wraparound(False)
cdef u64 sim_kad_apx(u8 *x, u8 *y):
    '''
    MEM-UNSAFE [x[0:NIH_LEN], y[0:NIH_LEN]]

    Approximate kademlia similarity, given by index of first bit at which the
    inputs differ, or 160 if they do not differ.

    Range [0, 160]
    '''

    cdef u64 out = 0
    cdef u8 byte_sim = 0
    cdef u64 ix = 0

    for ix in range(NIH_LEN):
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

cdef u32 randint(u32 mn, u32 mx):
    pass

