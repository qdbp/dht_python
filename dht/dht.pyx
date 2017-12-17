# cython: language_level=3, profile=True, wraparound=False
'''
Stateless DHT scraper.
'''
include "dht_h.pxi"

from atexit import register as atxreg
import asyncio as aio
from asyncio import sleep as asleep
from collections import Counter, deque
from functools import lru_cache, wraps
from itertools import zip_longest, repeat
import pickle
import os
import signal as sig
import MySQLdb as sql
import sys
import traceback as trc
from socket import inet_ntoa, inet_aton, socket
from socket import AF_INET, SOCK_DGRAM, SO_BINDTODEVICE
from time import time, monotonic

import numpy as np
from numpy.random import bytes as rbytes, random, randint
from uvloop import new_event_loop as new_uv_loop

from vnv.util import save_pickle, load_pickle
from vnv.log import get_logger

from libc.stdio cimport FILE, fopen, fwrite, fclose, fread, sprintf
from libc.string cimport memcmp, memset, memcpy
from libc.math cimport sqrt, fmin, fmax

# internal
from dht.util cimport LRUCache, LRU_EMTPY, LRU_NONE, sim_kad_apx, format_uptime
from dht.bdecode_st cimport parsed_msg, print_parsed_msg, krpc_bdecode
from dht.bdecode_st cimport bd_status_names
from dht.rt cimport rt_node_t, rt_info_t
# from dht.rt cimport upsert_pnode, rt_adj_quality

class BadState(Exception): pass


# from dht.bencode cimport bdecode_d

LOG = get_logger('dht')
sys.tracebacklimit = 1000

# net: sockets
DHT_LPORT = int(sys.argv[1])
DHT_LHOST = sys.argv[2]
if len(sys.argv) > 3:
    LOG.setLevel(int(sys.argv[3]))

cdef BOOTSTRAP = [('67.215.246.10', 6881)]

# dht: bootstrap, router.bittorrent.com

# info loop parameters

def in_data(fn):
    return './data/' + fn

# === global cdefs ===
cdef:
    struct mstd:
        double mean
        double std

    cdef struct dht_node_t:
        u8 nid[NIH_LEN]
        u8 pip[IP_LEN]
        u16 port

    u8 ZERO_ROW[NODEINFO_LEN]
    u8 SID_XOR[20]

    u8 BOOTSTRAP_PNODE[NODEINFO_LEN]


BOOTSTRAP_PNODE = list(
        b'2\xf5NisQ\xffJ\xec)\xcd\xba\xab\xf2\xfb\xe3F|\xc2g'
        b'\x00\x00\x00\x00\x00\x00'
    )
compact_peerinfo(BOOTSTRAP_PNODE + NIH_LEN, b'67.215.246.10', 6881)

SID_XOR = list(b'\x00\x00\x00submittothescrape')

memset(ZERO_ROW, 0, NODEINFO_LEN)

# === stats codes ===

# FIXME: take out to vnv
def aio_loop_method(double sleep_time, double init_sleep=1e-3):
    def decorator(f):
        @wraps(f)
        async def looped(self):

            cdef:
                double mark

            if init_sleep is not None:
                await asleep(init_sleep)

            mark = monotonic()
            while True:
                mark = mark + sleep_time
                try:
                    f(self)
                except Exception as e:
                    LOG.error(
                        f'Unhandled error in {f.__qualname__}\n' +
                        trc.format_exc()
                    )
                await asleep(max(mark - monotonic(), 1e-4))

        return looped
    return decorator

cdef class DHTListener:
    '''
    Asynchtonous listener for incoming messages.

    Implements a protocol api.
    '''

    cdef:
        DHTScraper scraper
        object transport
        u64 _do_drop

    def __init__(self, scraper):
        self.scraper = scraper

    cdef void send_msg(
            self,
            bytes msg,
            tuple addr,
            u64   prio,
            u8    ctl_byte,
            ST    stat_code):

        '''
        Ctl byte should be nid-constant but random over nids.

        Used to selectively drop messages to throttle. Lowest byte is a good
        choice.
        '''

        if prio == 0 and self._do_drop:
            self.scraper.cnt[<int>ST.tx_msg_drop_overflow] += 1
        elif prio == 1 or ctl_byte <= 255 * self.scraper.ctl_reply_rate:
            self.scraper.cnt[<int>ST.tx_tot] += 1
            self.scraper.cnt[<int>stat_code] += 1
            self.transport.sendto(msg, addr)
        else:
            self.scraper.cnt[<int>ST.tx_msg_drop_throt] += 1

    cpdef void connection_made(self, object transport):
        LOG.info('Connection made.')
        self.transport = transport

    cpdef void error_received(self, object exc):
        self.scraper.cnt[<int>ST.rx_err_received] += 1

    cpdef void datagram_received(self, bytes data, tuple saddr):
        try:
            self.scraper.handle_msg(data, saddr)
            self.scraper.cnt[<int>ST.rx_tot] += 1
        except OSError as e:
            self.scraper.cnt[<int>ST.rx_oserr] += 1
        except Exception as e:
            self.scraper.cnt[<int>ST.err_rx_exc] += 1
            LOG.error(f'Unhandled error in handle_raw_msg\n{trc.format_exc()}')

    cpdef void pause_writing(self):
        self._do_drop = 1

    cpdef void resume_writing(self):
        self._do_drop = 0

cdef class DHTScraper:

    cdef:
        # data objects
        # object naked_ihashes
        LRUCache naked_ihashes
        u8 rt[256][256][256][NODEINFO_LEN]
        u8 rt_qual[256][256][256]

        # in-flight dicts
        dict _ifl_dict
        set _ifl_ih_hold

        # runtime objects
        DHTListener listener
        object loop

        # db objects
        object _db_conn
        object _db

        # control variables
        u64 ctl_ifl_target
        double ctl_ihash_discard
        double ctl_ihash_refresh
        double ctl_timeout
        double ctl_ping_rate
        # curtail own r_gp if we're flooded
        double ctl_reply_rate

        # counters
        u64 cnt      [<int>ST._ST_ENUM_END]
        u64 _disp_cnt[<int>ST._ST_ENUM_END]
        u64 _ctl_cnt [<int>ST._ST_ENUM_END]

        # internal control variables
        float _start_time
        u64 _info_iter
        double _info_mark
        double _control_mark

        double _rtt_buf[RTT_BUF_LEN]
        u64 _rtt_buf_ix

        u64 _dkad_buf[DKAD_BUF_LEN]
        u64 _dkad_buf_ix

        # caches and pools for I/O ops
        list _db_row_pool
        dict _db_desc_pool
        set _db_new_ih_staging
        dict _ih_gp_holdoff
        dict _ih_db_holdoff
        LRUCache _ih_recent_peer_cache

        # NEW RT
        rt_node_t rt_root


    def __cinit__(self):
        # == DHT ==
        # plain list of known infohashes
        # self.naked_ihashes = deque([], maxlen=IH_POOL_LEN)  # type: ignore
        self.naked_ihashes = LRUCache(IH_POOL_LEN)  # type: ignore

        self._ifl_dict = {}
        self._ifl_ih_hold = set()

        # counter for various statistics of interest, reset every report cycle
        for ix in range(<int>ST._ST_ENUM_END):
            self.cnt[ix] = self._disp_cnt[ix] = self._ctl_cnt[ix] = 0

        self.listener = DHTListener(self)

        self.loop = new_uv_loop()

        # self._db = self._db_conn.cursor()
        self._db_conn = sql.connect(
            unix_socket='/run/mysqld/mysqld.sock',
            user='data',
            db='dht',
        )
        self._db = self._db_conn.cursor()

        atxreg(self._db_conn.close)
        atxreg(self._db_conn.commit)

        # internal flag variables
        self._info_iter = 0
        self._info_mark = 0.
        self._control_mark = 0.

        self._rtt_buf_ix = 0
        for i in range(RTT_BUF_LEN):
            self._rtt_buf[i] = 0.2

        self._dkad_buf_ix = 0
        for i in range(DKAD_BUF_LEN):
            self._dkad_buf[i] = 0

        self._db_row_pool = []
        self._db_desc_pool = {}
        self._db_new_ih_staging = set()
        self._ih_gp_holdoff = {}
        self._ih_db_holdoff = {}
        self._ih_recent_peer_cache = LRUCache(RECENT_PEER_CACHESIZE)

        # control variables
        self.ctl_ifl_target = BASE_IFL_TARGET
        self.ctl_ihash_discard = BASE_IHASH_DISCARD
        self.ctl_ihash_refresh = BASE_IHASH_REFRESH
        self.ctl_timeout = BASE_GP_TIMEOUT
        self.ctl_ping_rate = BASE_PING_RATE
        self.ctl_reply_rate = 1.0

        # NEW RT
        # upsert_pnode(&self.rt_root, BOOTSTRAP_PNODE, 0x07)

    @cython.profile(False)
    cdef inline u8* rt_get_cell(self, u8 *nid):
        '''
        Returns the index in the routing table corresponding to the given
        nid. Obviously not injective.

        ASSUMES 8 CONTACTS AT DEPTH 3
        '''
        cdef:
            u8 ax = nid[0]
            u8 bx = nid[1]
            u8 cx = nid[2]
            # u8 cx = (nid[2] & 0xe0) >> 5

        return self.rt[ax][bx][cx]

    # XXX consolidate rt_qual into rt?
    @cython.profile(False)
    cdef inline u8* rt_get_qual_cell(self, u8 *nid):
        '''
        Returns the index in the quality table corresponding to the given
        nid. Obviously not injective.

        ASSUMES 8 CONTACTS AT DEPTH 3
        '''
        cdef:
            u8 ax = nid[0]
            u8 bx = nid[1]
            u8 cx = nid[2]
            # u8 cx = (nid[2] & 0xe0) >> 5

        return &self.rt_qual[ax][bx][cx]

    @cython.profile(False)
    cdef u64 rt_add_sender_as_contact(
            self,
            parsed_msg *krpc,
            tuple       addr,
            u8          base_qual):

        cdef u8 sender_pnode[NODEINFO_LEN]
        cdef bint good_addr
        cdef u64 rep_status

        memcpy(sender_pnode, krpc.nid, NIH_LEN)

        good_addr = compact_peerinfo(sender_pnode + NIH_LEN, addr[0], addr[1])
        if not good_addr:
            self.cnt[<int>ST.rt_replace_invalid] += 1
            return RT_REP_INVALID_NODE

        rep_status = self.rt_random_replace_contact(sender_pnode, base_qual)

        if rep_status == RT_REP_SUCCESS:
            self.cnt[<int>ST.rt_replace_accept] += 1
        elif rep_status == RT_REP_NO_EVICT:
            self.cnt[<int>ST.rt_replace_reject] += 1
        else:
            self.cnt[<int>ST.rt_replace_invalid] += 1

        return rep_status

    @cython.profile(False)
    cdef u64 rt_random_replace_contact(self, u8 *new_pnode, u8 base_qual):
        '''
        Possibly randomly replaces the contact for `new_pnode` in the routing
        table.

        The old contact has a chance to be evicted inversely related to
        its quality given by the quality table.

        If no contact is evicted, the new_contact is simply ignored.
        '''

        cdef u8* node_spot = self.rt_get_cell(new_pnode)
        cdef u8* qual_cell = self.rt_get_qual_cell(new_pnode)

        if check_evict(qual_cell[0], base_qual):
            if validate_nodeinfo(new_pnode):
                memcpy(node_spot, new_pnode, NODEINFO_LEN)
                qual_cell[0] = base_qual if base_qual <= MAX_QUAL else MAX_QUAL
                return RT_REP_SUCCESS
            return RT_REP_INVALID_NODE
        return RT_REP_NO_EVICT

    cdef void rt_adj_quality(self, u8 *nid, i64 delta):
        '''
        Adjusts the quality of the routing contact "nid", if it
        can be found. Otherwise, does nothing.
        '''

        cdef u8 *qual_cell = self.rt_get_qual_cell(nid)
        cdef u8 *cur_nodeinfo = self.rt_get_cell(nid)
        cdef i8 new_qual

        # the contact we're trying to adjust has been replaced
        # just do nothing in this case
        if not is_row_equal(nid, cur_nodeinfo, NIH_LEN):
            return

        new_qual = qual_cell[0] + delta
        if new_qual < MIN_QUAL:
            new_qual = MIN_QUAL
        elif new_qual > MAX_QUAL:
            new_qual = MAX_QUAL
        qual_cell[0] = new_qual

    cdef u8* rt_get_valid_neighbor_contact(self, u8 *target):
        '''
        Returns a nid from the array of nids `narr` whose first two bytes
        match the target.
        '''

        cdef u8 *neighbor_cell = self.rt_get_cell(target)
        cdef u64 ix

        if not is_row_empty(neighbor_cell):
            return neighbor_cell

        # XXX: maybe check near neighbors; hard to guarantee "near" in rt
        # ordering under kad distance
        self.cnt[<int>ST.rt_miss] += 1
        return NULL

    cdef u8* rt_get_random_valid_node(self):
        '''
        Returns a random non-zero, valid node from the current routing table.

        Is much slower when the table is empty. Returns None if it can
        find no node at all.
        '''

        cdef:
            u64 start_ix = randint(0, RT_TOTAL_CONTACTS)
            u64 ix, jx, ax, bx, cx

        for ix in range(0, RT_TOTAL_CONTACTS):
            jx = (start_ix + ix) % RT_TOTAL_CONTACTS
            ax = jx >> 16
            bx = (jx >> 8) & 0xff
            cx = jx & 0xff
            if validate_nodeinfo(self.rt[ax][bx][cx]):
                return self.rt[ax][bx][cx]
            elif not is_row_empty(self.rt[ax][bx][cx]):
                memset(self.rt[ax][bx][cx], 0, NODEINFO_LEN)
                self.rt_qual[ax][bx][cx] = MIN_QUAL

        self.cnt[<int>ST.err_rt_no_contacts] += 1
        LOG.error('Could not find any random valid contact. RT in trouble!')
        return NULL

    cdef void db_update_peers(self, bytes ih, list peers):
        '''
        Insets the peer information for the given ih into the database.

        Expects clean input. Desc should be utf-8 encoded.
        '''
        cdef:
            float t = time()
            bytes addr
            list ihs
            u16 port

        cdef cur_time = monotonic()

        self.cnt[<int>ST.db_update_peers] += 1

        for peerinfo in peers:
            self._db_row_pool.append((ih, peerinfo))

        if len(self._db_row_pool) > ROW_POOL_MAXLEN:
            # NOTE: make sure delete-cascade is respected if this method
            # is ever changed
            self._db.executemany(
                '''
                INSERT INTO `metainfo` (`info_hash`) VALUES (%s)
                ON DUPLICATE KEY UPDATE `info_hash` = `info_hash`
                ''',
                [(row[0],) for row in self._db_row_pool],
            )
            self._db.executemany(
                '''
                REPLACE INTO `peerinfo` (`info_hash`, `addr_port`)
                VALUES (%s, %s)
                ''',
                self._db_row_pool,
            )

            cur_time = monotonic()
            for ih in {row[0] for row in self._db_row_pool}:
                if ih in self._ih_db_holdoff:
                    del self._ih_db_holdoff[ih]
                self._ih_recent_peer_cache.insert(ih, cur_time)

            self.cnt[<int>ST.db_rows_inserted] += len(self._db_row_pool)
            self._db_row_pool.clear()

    cdef void ping_new_nodes(self, u8 *pnodes, u64 n_nodes):
        '''
        Generic processor for all new found nodes.

        Sends out pings to qualifying nodes to referesh the routing table.
        '''

        cdef u64 offset, status_code
        cdef bint did_replace
        cdef dht_node_t ping_contact
        cdef u8 bitmask = 0
        cdef u8 zx

        for offset in range(0, NODEINFO_LEN * n_nodes, NODEINFO_LEN):

            # bitmask keeps track of which cx indices we have inserted already
            # this call; this is sufficient since most calls share ax and bx
            zx = 1 << ((pnodes[offset + 2] & 0xe0) >> 5)
            if zx & bitmask:
                self.cnt[<int>ST.rt_newnode_drop_dup] += 1
                continue

            elif random() > self.ctl_ping_rate:
                self.cnt[<int>ST.rt_newnode_drop_luck] += 1
                continue

            bitmask |= zx

            if uncompact_nodeinfo(&ping_contact, pnodes + offset):
                self.send_q_pg(&ping_contact)
                self.cnt[<int>ST.rt_newnode_ping] += 1
            else:
                self.cnt[<int>ST.rt_newnode_invalid] += 1

    @cython.profile(False)
    cdef inline object get_in_flight(self, bytes nid):
        return self._ifl_dict.get(nid)

    cdef bint put_in_flight(self, bytes nid, bytes ih):
        if ih in self._ifl_ih_hold:
            return 0
        else:
            self._ifl_dict[nid] = (ih, monotonic())
            self._ifl_ih_hold.add(ih)
            return 1

    cdef void replace_in_flight(self, bytes old_nid, bytes new_nid):
        ih = self._ifl_dict[old_nid][0]
        del self._ifl_dict[old_nid]
        self._ifl_dict[new_nid] = (ih, monotonic())

    cdef bint del_in_flight(self, bytes nid):
        if nid in self._ifl_dict:
            ih = self._ifl_dict[nid][0]
            del self._ifl_dict[nid]
            self._ifl_ih_hold.remove(ih)
            return 1
        else:
            return 0

    cdef void handle_gp_nodes(self, parsed_msg *krpc, tuple saddr):
        '''
        Processes nodes received in a get_peers reply.

        Checks whether the we have an infohash tied to the reply, whether
        the nodes received are suitable, and if yes, follows up with the
        next node.
        '''

        cdef dht_node_t followup_contact
        cdef u64 base_sim, cur_sim, best_sim
        cdef int offset
        cdef int best_offset = -1
        cdef double insert_time
        cdef bytes ih
        cdef bint got_bad_node = 0
        cdef bint good

        old_nid = krpc.nid[0:NIH_LEN]

        ifl_rec = self.get_in_flight(old_nid)

        if ifl_rec is None:
            self.cnt[<int>ST.ih_nodes_unmatched] += 1
            return

        ih, insert_time = ifl_rec

        self._rtt_buf[self._rtt_buf_ix] = monotonic() - insert_time
        self._rtt_buf_ix = (self._rtt_buf_ix + 1) % RTT_BUF_LEN

        base_sim = best_sim = sim_kad_apx(old_nid, ih)

        for offset in range(0, krpc.n_nodes * NODEINFO_LEN, NODEINFO_LEN):

            if not uncompact_nodeinfo(&followup_contact, krpc.nodes + offset):
                got_bad_node = 1
                continue

            cur_sim = sim_kad_apx(followup_contact.nid, ih)

            if cur_sim < base_sim:
                got_bad_node = 1
                continue

            # accept same sim to get a new node
            if cur_sim >= best_sim:
                best_sim = cur_sim
                best_offset = offset

        if best_offset < 0:
            self.cnt[<int>ST.bm_nodes_invalid] += 1
            self.rt_adj_quality(old_nid, -3)
            return
        elif got_bad_node:
            self.rt_adj_quality(old_nid, 1)
        else:
            self.rt_adj_quality(old_nid, 3)

        self.cnt[<int>ST.ih_nodes_matched] += 1
        uncompact_nodeinfo(&followup_contact, krpc.nodes + best_offset)

        self._dkad_buf[self._dkad_buf_ix] = best_sim - base_sim
        self._dkad_buf_ix = (self._dkad_buf_ix + 1) % DKAD_BUF_LEN

        self.send_q_gp(ih, &followup_contact, 1)
        self.replace_in_flight(old_nid, followup_contact.nid[0:NIH_LEN])


    cdef void handle_new_peers(self, u8 *nid, u8 *peers, u64 n_peers):

        cdef list good_peers = []
        cdef u64 offset
        cdef u16 port
        cdef object maybe_ih
        cdef bint got_bad_peer = 0

        maybe_ih = self.get_in_flight(nid[0:NIH_LEN])

        if maybe_ih is not None:

            self.cnt[<int>ST.ih_peers_matched] += 1

            for offset in range(0, n_peers * PEERINFO_LEN, PEERINFO_LEN):

                if not validate_peerinfo(peers + offset):
                    got_bad_peer = 1
                    continue

                good_peers.append(peers[offset:offset + 6])

        else:
            self.cnt[<int>ST.ih_peers_unmatched] += 1
            return

        if len(good_peers) == 0:
            self.cnt[<int>ST.bm_peers_bad] += 1
            self.rt_adj_quality(nid, -3)
            return

        elif got_bad_peer:
            self.rt_adj_quality(nid, -1)

        self.db_update_peers(maybe_ih[0], good_peers)
        self.del_in_flight(nid[0:NIH_LEN])

    # XXX get rid of tuple conversion
    cdef void handle_msg(self, bytes d, tuple saddr):

        cdef parsed_msg krpc
        cdef u64 status
        cdef u64 replace_status
        cdef u16 ap_port
        cdef str decoded_name
        cdef bytes ih, raw_ap_name

        saddr = (saddr[0].encode('ascii'), saddr[1])

        status = krpc_bdecode(d, &krpc)
        self.cnt[status] += 1

        if status != ST.bd_a_no_error:
            IF BD_TRACE:
                if status == ST.err_bd_fallthrough:
                    print('')
                    print(d)
                    print('\n'.join(g_trace))
            return

        if krpc.method == MSG_Q_AP:
            self.cnt[<int>ST.rx_q_ap] += 1

            replace_status = self.rt_add_sender_as_contact(&krpc, saddr, 3)

            if krpc.token_len != 1 or krpc.token[0] != TOKEN:
                self.cnt[<int>ST.bm_ap_bad_token] += 1
                return

            if krpc.ap_implied_port:
                ap_port = <u16> saddr[1]
            else:
                ap_port = krpc.ap_port

            ih = krpc.ih[0:NIH_LEN]

            if krpc.ap_name_len > 0:

                raw_ap_name = krpc.ap_name[0:krpc.ap_name_len]

                try:
                    # XXX faster utf8 checking
                    decoded_name = raw_ap_name.decode('utf-8')
                except UnicodeDecodeError:
                    self.cnt[<int>ST.bm_ap_bad_name] += 1
                    return

                self._db_desc_pool[ih] = raw_ap_name

            self.db_update_peers(ih, [compact_peerinfo_bytes(saddr[0], ap_port)])
            self.send_r_pg(krpc.nid, krpc.tok[0:krpc.tok_len], saddr, 1)

        elif krpc.method == MSG_Q_FN:
            self.cnt[<int>ST.rx_q_fn] += 1
            self.rt_add_sender_as_contact(&krpc, saddr, 2)

            pnode = self.rt_get_valid_neighbor_contact(krpc.target[0:NIH_LEN])
            if pnode != NULL:
                self.send_r_fn(
                    pnode, krpc.nid, krpc.tok[0:krpc.tok_len], saddr)

        elif krpc.method == MSG_Q_GP:
            self.cnt[<int>ST.rx_q_gp] += 1
            self.rt_add_sender_as_contact(&krpc, saddr, 2)
            # FIXME this check is too slow, need to move to rolling bloom
            # filters

            new_ih = krpc.ih[0:NIH_LEN]
            if random() > self.ctl_ihash_discard:
                self.cnt[<int>ST.ih_move_rx_to_staging] += 1
                self._db_new_ih_staging.add(new_ih)

            pnode = self.rt_get_valid_neighbor_contact(krpc.ih)
            if pnode != NULL:
                self.send_r_gp(
                    pnode, krpc.nid, krpc.tok[0:krpc.tok_len], saddr)

        elif krpc.method == MSG_Q_PG:
            self.cnt[<int>ST.rx_q_pg] += 1
            self.rt_add_sender_as_contact(&krpc, saddr, 1)

            self.send_r_pg(krpc.nid, krpc.tok[0:krpc.tok_len], saddr, 0)

        elif krpc.method == MSG_R_GP:
            self.cnt[<int>ST.rx_r_gp] += 1

            if krpc.n_peers > 0:
                self.cnt[<int>ST.rx_r_gp_values] += 1
                self.handle_new_peers(krpc.nid, krpc.peers, krpc.n_peers)

            # NOTE yes, ignore nodes from responses with peers
            elif krpc.n_nodes > 0:
                self.cnt[<int>ST.rx_r_gp_nodes] += 1
                self.ping_new_nodes(krpc.nodes, krpc.n_nodes)
                self.handle_gp_nodes(&krpc, saddr)

            elif krpc.n_peers + krpc.n_nodes == 0:
                IF BD_TRACE:
                        print('EMPTY PEERS IN R_GP')
                        print(d)
                        print('\n'.join(g_trace))
                        return
                self.cnt[<int>ST.err_bd_empty_r_gp] += 1

        elif krpc.method == MSG_R_FN:
            self.cnt[<int>ST.rx_r_fn] += 1
            if krpc.n_nodes == 0:
                IF BD_TRACE:
                    print('EMPTY NODES IN R_FN')
                    print(d)
                    print('\n'.join(g_trace))
                    return
                self.cnt[<int>ST.err_bd_empty_r_gp] += 1

            # these nodes are usually close, so set only one
            self.ping_new_nodes(krpc.nodes, 1)

        elif krpc.method == MSG_R_PG:
            self.rt_add_sender_as_contact(&krpc, saddr, 2)
            self.cnt[<int>ST.rx_r_pg] += 1

        else:
            IF BD_TRACE:
                print('HANDLE FALLTHROUGH')
                print(d)
                print('\n'.join(g_trace))
            self.cnt[<int>ST.err_bd_handle_fallthrough] += 1

    # FIXME implement
    cdef void send_sample_infohashes(self, bytes nid, tuple addr):
        pass

    cdef void send_q_fn_random(self, dht_node_t *dest):
        cdef bytearray random_target = bytearray(rbytes(20))
        random_target[0] = dest.nid[0]
        random_target[1] = dest.nid[1]
        random_target[2] = dest.nid[2]
        random_target[3] = dest.nid[3]
        self.send_q_fn(rbytes(NIH_LEN), dest)

    cdef void send_q_fn(self, u8 *target, dht_node_t *dest):
        '''
        Solicit a new random node based on our current self id and the current
        state
        '''
        cdef u8 msg_buf[Q_FN_LEN]

        memcpy(msg_buf,                      Q_FN_PROTO, Q_FN_LEN)
        memcpy(msg_buf + Q_FN_TARGET_OFFSET, target,     NIH_LEN)
        mk_sid_raw(msg_buf + Q_FN_SID_OFFSET, dest.nid)

        # XXX bytes conversion
        self.listener.send_msg(
            msg_buf[:Q_FN_LEN], mk_addr_from_dht_node(dest),
            0, dest.nid[NIH_LEN - 1],
            ST.tx_q_fn,
        )

    cdef void send_q_gp(self, u8 *ih, dht_node_t *dest, u64 prio):
        '''
        Send get_peers query.
        '''
        cdef u8 msg_buf[Q_GP_LEN]

        memcpy(    msg_buf,                   Q_GP_PROTO, Q_GP_LEN)
        memcpy(    msg_buf + Q_GP_IH_OFFSET,  ih,         NIH_LEN)
        mk_sid_raw(msg_buf + Q_GP_SID_OFFSET, dest.nid)

        # XXX bytes conversion
        self.listener.send_msg(
            msg_buf[:Q_GP_LEN], mk_addr_from_dht_node(dest),
            prio, dest.nid[NIH_LEN - 1],
            ST.tx_q_gp,
        )

        # print(msg_buf[:Q_GP_LEN])

    cdef void send_q_pg(self, dht_node_t *dest):
        cdef u8 msg_buf[Q_PG_LEN]

        memcpy(msg_buf, Q_PG_PROTO, Q_PG_LEN)
        mk_sid_raw(msg_buf + Q_PG_SID_OFFSET, dest.nid)

        # XXX bytes conversion
        self.listener.send_msg(
            msg_buf[:Q_PG_LEN], mk_addr_from_dht_node(dest),
            0,
            dest.nid[NIH_LEN - 1],
            ST.tx_q_pg,
        )

    cdef void send_r_fn(self, u8 *pnode, u8 *nid, bytes tok, tuple addr):
        self.listener.send_msg(
            (
                b'd1:rd2:id20:' + mk_sid(nid) +
                b'5:nodes26:' + bytes(pnode[0:NODEINFO_LEN]) +
                b'e1:t' + bencode_tok(tok) + b'1:y1:re'
            ),
            addr,
            0,
            nid[NIH_LEN - 1],
            ST.tx_r_fn,
        )

    cdef void send_r_pg(self, u8 *nid, bytes tok, tuple daddr, u64 prio):
        '''
        Send a ping reply.
        '''
        self.listener.send_msg(
            (
                b'd1:rd2:id20:' + mk_sid(nid) + b'e1:t' +
                bencode_tok(tok) + b'1:y1:re'
            ),
            daddr,
            prio,
            nid[NIH_LEN - 1],
            ST.tx_r_pg,
        )

    cdef void send_r_gp(self, u8 *pnode, u8 *nid, bytes tok, tuple addr):
        '''
        Send get_peers response.

        Includes one packed node of length 26.
        '''
        self.listener.send_msg(
            (
                b'd1:rd2:id20:' + mk_sid(nid) +
                b'5:token1:\x885:nodes26:' + bytes(pnode[0:NODEINFO_LEN]) +
                b'e1:t' + bencode_tok(tok) + b'1:y1:re'
            ),
            addr,
            0,
            nid[NIH_LEN - 1],
            ST.tx_r_gp,
        )

    @aio_loop_method(GP_SLEEP)
    def loop_get_peers(self):

        cdef dht_node_t gp_contact
        cdef u8 *pnode
        cdef bytes bnid, ih
        cdef object val

        while len(self._ifl_dict) < self.ctl_ifl_target:

            val = self.naked_ihashes.poptail()

            if val is LRU_EMTPY:
                self.cnt[<int>ST.ih_naked_exhausted] += 1
                pnode = self.rt_get_random_valid_node()
                if pnode != NULL:
                    if uncompact_nodeinfo(&gp_contact, pnode):
                        self.send_q_fn_random(&gp_contact)
                    else:
                        self.cnt[<int>ST.err_rt_pulled_bad_node] += 1
                return

            ih = val[0]

            # try to get a node close to the infohash
            pnode = self.rt_get_valid_neighbor_contact(ih)
            if pnode != NULL:

                if not uncompact_nodeinfo(&gp_contact, pnode):
                    self.cnt[<int>ST.err_rt_pulled_bad_node] += 1
                    continue

                nid = gp_contact.nid[0:NIH_LEN]

                if nid in self._ifl_dict:
                    self.cnt[<int>ST.ih_move_naked_duplicate] += 1
                else:
                    self.send_q_gp(ih, &gp_contact, 1)
                    self._ih_gp_holdoff[ih] = monotonic()
                    self.put_in_flight(nid, ih)
                    self.cnt[<int>ST.ih_move_naked_to_hold] += 1
                continue

            pnode = self.rt_get_random_valid_node()
            if pnode != NULL:
                if uncompact_nodeinfo(&gp_contact, pnode):
                    self.send_q_fn(ih, &gp_contact)
                else:
                    self.cnt[<int>ST.err_rt_pulled_bad_node] += 1

    @aio_loop_method(FP_SLEEP)
    def loop_find_nodes(self):
        '''
        Send out find_node randomly.

        The goal is to inject ourselves into as many nodes' routing tables
        as possible, and to refresh the routing table.
        '''

        cdef dht_node_t fn_contact
        cdef u8 *pnode

        pnode = self.rt_get_random_valid_node()
        if pnode != NULL:
            if uncompact_nodeinfo(&fn_contact, pnode):
                self.send_q_fn_random(&fn_contact)
            else:
                self.cnt[<int>ST.err_rt_pulled_bad_node] += 1

    @aio_loop_method(HO_PURGE_SLEEP)
    def loop_purge_holdoffs(self):

        # gp holdoff
        cdef double purge_thresh = monotonic() - BASE_IH_GP_HOLDOFF

        cdef set unhold_ihs = {
            ih for ih, t in self._ih_gp_holdoff.items()
            if t < purge_thresh
        }

        for unih in unhold_ihs:
            self._db_new_ih_staging.add(unih)
            del self._ih_gp_holdoff[unih]
        self.cnt[<int>ST.ih_move_hold_to_staging] += len(unhold_ihs)

        # db holdoff
        purge_thresh = monotonic() - BASE_IH_DB_HOLDOFF

        unhold_ihs = {
            ih for ih, t in self._ih_db_holdoff.items()
            if t < purge_thresh
        }

        for unih in unhold_ihs:
            del self._ih_db_holdoff[unih]
        self.cnt[<int>ST.ih_unhold_db] += len(unhold_ihs)

    @aio_loop_method(PURGE_SLEEP, init_sleep=5.0)
    def loop_purge_ifl(self):
        '''
        Purges the in-flight state to remove timed-out requests.

        Downvotes nodes to which requests timed out.
        '''

        cdef double cur_time = monotonic()
        cdef double timeout_thresh = cur_time - self.ctl_timeout
        cdef double put_time
        cdef bytes nid, ih
        cdef dict bad_nids = {}  # nid: is nid unconsumed?

        bad_nids = {
            nid: ih
            for nid, (ih, put_time) in self._ifl_dict.items()
            if put_time < timeout_thresh
        }

        for nid, ih in bad_nids.items():
            del self._ifl_dict[nid]
            self._ifl_ih_hold.remove(ih)
            self.rt_adj_quality(nid, -2)

    @aio_loop_method(IH_DESC_SLEEP, init_sleep=IH_DESC_SLEEP)
    def loop_dump_descs(self):
        '''
        Dump descriptions sniffed through q_ap's to the database.
        '''

        # NOTE need the two vs for the update syntax
        cdef list linear_descs = sorted(
            [{'ih': k, 'desc': v} for k, v in self._db_desc_pool.items()],
            key=lambda x: x['ih']
        )
        self._db_desc_pool.clear()

        self._db.executemany(
            '''
            UPDATE `metainfo`
            SET `description`=%(desc)s
            WHERE `info_hash`=%(ih)s
            ''',
            linear_descs,
        )

    #XXX cdef coroutines?
    @aio_loop_method(IH_STAGE_SLEEP, init_sleep=0.25)
    def loop_stage_new_ihashes(self):
        '''
        Efficient bulk lookup of info_hash last seen timestamps
        using a temporary table.
        '''

        self.cnt[<int>ST.ih_stage_n_raw] += len(self._db_new_ih_staging)
        # first, exclude held-off and in-flight keys
        cdef set base_stage_ihs = self._db_new_ih_staging.difference(
            self._ih_gp_holdoff.keys(),
            self.naked_ihashes.d.keys(),
            self._ih_recent_peer_cache.d.keys(),
            self._ifl_ih_hold,
        )
        self.cnt[<int>ST.ih_stage_n_prefiltered] += len(base_stage_ihs)

        # keys in the ih_db_holdoff set have passed the database test recently
        # and so are set to be staged
        cdef set recycled_ihs = base_stage_ihs & self._ih_db_holdoff.keys()

        # base_stage_keys\recycled_ihs are the ones we need to look up
        cdef list ihs_to_lookup = sorted(
            base_stage_ihs - self._ih_db_holdoff.keys()
        )

        self.cnt[<int>ST.ih_stage_n_recycled] += len(recycled_ihs)
        self.cnt[<int>ST.ih_stage_n_lookup] += len(ihs_to_lookup)

        self._db_new_ih_staging.clear()

        # clear current scratch table
        self._db.execute(
            '''
            DELETE FROM cand_ihashes
            '''
        )
        # insert current query infohashes (as single transaction) into
        # the search table
        self._db.executemany(
            '''
            INSERT INTO `cand_ihashes` (`info_hash`)
            VALUES (%s)
            ''',
            ihs_to_lookup,
        )
        # batch lookup the timestamps (potentially null for new ihs)
        self._db.execute(
            '''
            SELECT DISTINCT
                `cand_ihashes`.`info_hash`
            FROM
                `cand_ihashes`
                LEFT JOIN
                    `peerinfo`
                ON
                    `cand_ihashes`.`info_hash` = `peerinfo`.`info_hash`
            WHERE
                (`peerinfo`.`timestamp` IS NULL)
                OR
                ADDDATE(`peerinfo`.`timestamp`, INTERVAL 259200 SECOND) < NOW()
            '''
        )

        cdef list ih_results = [row[0] for row in self._db.fetchall()]
        cdef double cur_time = monotonic()

        for recycled_ih in recycled_ihs:
            self.naked_ihashes.insert(recycled_ih, cur_time)

        self.cnt[<int>ST.ih_move_staging_to_naked] += len(ih_results)
        self.cnt[<int>ST.ih_move_staging_to_naked] += len(recycled_ihs)

        for staged_ih in ih_results:
            self._ih_db_holdoff[staged_ih] = cur_time
            self.naked_ihashes.insert(staged_ih, cur_time)

    @aio_loop_method(BOOTSTRAP_SLEEP, init_sleep=BOOTSTRAP_SLEEP)
    def loop_bootstrap(self):
        cdef dht_node_t new_contact

        if self.metric_rt_fullness() < 0.01:
            for addr in BOOTSTRAP:
                # FIXME this is a lot of useless conversion an deconversion
                # harmless in low freq. bootstrap, but still...
                memcpy_bytes(new_contact.nid, rbytes(NIH_LEN), NIH_LEN)
                memcpy_bytes(new_contact.pip, inet_aton(addr[0]), IP_LEN)
                new_contact.port = addr[1]

                self.send_q_fn_random(&new_contact)

    @aio_loop_method(SAVE_SLEEP, init_sleep=SAVE_SLEEP)
    def loop_save_data(self):
        self.dump_data()
        self._db_conn.commit()

    @aio_loop_method(CONTROL_SLEEP, init_sleep=CONTROL_SLEEP)
    def loop_control(self):
        '''
        Tracks and dynamically updates parameters controlling the operation
        of the scraper to optimize performance.
        '''

        cdef double t = monotonic()
        cdef double dt = t - self._control_mark
        cdef int ix

        self._control_mark = t
        dcnt = Counter()
        for ix in range(<int>ST._ST_ENUM_END):
            dcnt[<bytes>ST_names[ix]] += (self.cnt[ix] - self._ctl_cnt[ix])
            self._ctl_cnt[ix] = self.cnt[ix]

        cdef double gpps = dcnt['rx_q_gp'] / dt

        self.ctl_reply_rate = min(1.0, GPPS_RX_TARGET / (1 + gpps))

        self.ctl_ihash_discard = len(self.naked_ihashes) / IH_POOL_LEN
        self.ctl_ping_rate = (1 - self.ctl_ihash_discard)

        rtt_stat = self.metric_gp_rtt()
        self.ctl_timeout = max(0.5, rtt_stat.mean + 3 * rtt_stat.std)

    @aio_loop_method(INFO_SLEEP, init_sleep=INFO_SLEEP)
    def loop_info(self):

        cdef double t = monotonic()
        cdef double dt = t - self._info_mark
        cdef int ix

        self._info_mark = t

        dcnt = Counter()
        printcnt = Counter()
        for ix in range(<int>ST._ST_ENUM_END):
            printcnt[<bytes>ST_names[ix].decode('ascii')] = self.cnt[ix]
            if self.cnt[ix] != self._disp_cnt[ix]:
                dcnt[<bytes>ST_names[ix].decode('ascii')] =\
                    (self.cnt[ix] - self._disp_cnt[ix])
                self._disp_cnt[ix] = self.cnt[ix]

            # print(self.cnt[ix], ST_names[ix].decode('ascii'))

        # get peers response rate
        gprr = min(1.0, dcnt["rx_r_gp"] / (dcnt["tx_q_gp"] + 1))
        # values to nodes ratio (in gp_response)
        vnr = (dcnt["rx_r_gp_values"] + 1) / (dcnt["rx_r_gp_nodes"] + 1)
        # db accept rate (number of new infohashes not in db already)
        newih, allih = dcnt["ih_staged_new"] + 1, dcnt["ih_staged_db_lookup"] + 1
        newr = newih / allih

        # get peers round trip time
        rtt = self.metric_gp_rtt()

        # routing table replacement rate
        rts = dcnt["rt_replace_accept"] + 1
        rtf = dcnt["rt_replace_reject"] + 1
        rtx = dcnt["rt_replace_invalid"] + 1
        rt_rr  = rts / (rts + rtf + rtx)

        newr = (dcnt["ih_move_staging_to_naked"] + 1) /\
            (dcnt["ih_stage_n_prefiltered"] + 1)

        x = Counter(
            {k: int(v / dt) for k, v in dcnt.items() if v > 0}
        )

        printcnt['perf_rr_gp'] = gprr
        printcnt['perf_rr_fn'] =\
            min(1.0, (dcnt['rx_r_fn'] + 1) / (dcnt['tx_q_fn'] + 1))
        printcnt['perf_rr_pg'] =\
            min(1.0, (dcnt['rx_r_pg'] + 1) / (dcnt['tx_q_pg'] + 1))

        printcnt['perf_rr_tot'] = min(
            1.0,
            (
                dcnt['rx_r_fn'] +
                dcnt['rx_r_pg'] +
                dcnt['rx_r_gp'] + 1
            ) / (
                dcnt['tx_q_fn'] +
                dcnt['tx_q_pg'] +
                dcnt['tx_q_gp'] + 1
            )
        )

        printcnt['perf_net_rtt_ms'] = 1000. * rtt.mean
        printcnt['perf_net_rtt_ms_std'] = 1000. * rtt.std

        printcnt['perf_db_newr'] = newr

        printcnt['perf_rt_fullness'] = self.metric_rt_fullness()
        printcnt['perf_rt_qual'] = self.metric_av_quality()
        printcnt['perf_rt_replace_rate'] = rt_rr
        printcnt['perf_gp_av_dkad'] = self.metric_av_dkad()

        info = (
            f'{format_uptime(int(monotonic() - self._start_time)):>9s} | '  # len 11
            f'{x["rx_q_pg"]:>5d} '  # len 6
            f'{x["rx_q_fn"]:>5d} {x["rx_r_fn"]:>5d} '  # len 12
            f'{x["rx_q_gp"]:>5d} {x["rx_r_gp"]:>5d} '  # len 12
            f'{x["rx_q_ap"]:>5d} | '  # len 11
            f'{x["tx_q_fn"]:>5d} {x["tx_r_fn"]:>5d} {x["tx_q_gp"]:>5d} '  # len 18
            f'{x["tx_r_gp"]:>5d} {x["tx_q_pg"]:>5d} '  # len 12
            f'{x["tx_r_pg"]:>5d} | '  # len 6
            f'{x["db_update_peers"]:>4d} {x["db_rows_inserted"]:>5d} | ' #  len 13
            f'{x["ih_move_naked_to_hold"]:>5d} '
            f'{x["ih_move_rx_to_staging"]:>5d} '
            f'{x["ih_move_hold_to_staging"]:>5d} '
            f'{x["ih_move_staging_to_naked"]:>5d} | '
            f'{gprr:>4.2f}({self.ctl_reply_rate:>4.2f}) ' # len 11
            f'{self.ctl_ifl_target:>4d} {vnr:4.2f} '  # len 15
            f'{int(1000 * rtt.mean):>3d}±{int(1000 * rtt.std):>3d} | '  # len 10
            f'{self.metric_av_quality():>4.2f} {rt_rr:4.2f} ' # len 10
            f'{x["rt_missing_neighbor"]:>4d} | '  # len 11
        )

        header_high = (
            '--STATS---| '
            '---------------- RX --------------- | '
            '---------------- TX --------------- | '
            '--- DB --- | '
            '--------- IH ---------- | '
            '------------ PERF ---------- | '
            '----- RT ----- |'
        )

        header_low = (
            '  uptime  | '
            ' ping '
            '   fn  r_fn '
            '   gp  r_gp '
            '   ap | '
            '   fn  r_fn    gp '
            ' r_gp    pg  r_pg | '
            'dbup  dbnr | '
            ' n->h '
            'rx->s '
            ' h->s '
            ' s->n | '
            'gprr (own) '
            'load  vnr '
            'rtt(ms) | '
            'qual rtrr '
            'miss |'
        )

        if not self._info_iter:
            LOG.info(header_high)
            LOG.info(header_low)

        LOG.info(info)
        self._info_iter = (self._info_iter + 1) % INFO_HEADER_EVERY

        with open(INFO_FILE, 'w') as f:
            f.write(self.format_detailed_info(printcnt))

    def run(self):
        # XXX fixme cython time jitters all over the place on startup,
        # this can be later than the first time call in info(), causing
        # stupidity
        self._start_time = monotonic()
        self._info_mark = self._control_mark = monotonic()

        memset(self.rt, 0, 256 * 256 * 256 * NODEINFO_LEN)
        memset(self.rt_qual, 0, 256 * 256 * 256)

        self.load_data()

        run_listener = self.loop.create_datagram_endpoint(
            lambda: self.listener, local_addr=(DHT_LHOST, DHT_LPORT)
        )

        # order matters here
        tasks = [
            aio.ensure_future(task_loop, loop=self.loop) for task_loop in [
                run_listener,
                self.loop_info(),
                self.loop_control(),
                # self.loop_bootstrap(),  #  XXX as argument
                self.loop_stage_new_ihashes(),
                self.loop_dump_descs(),
                self.loop_purge_ifl(),
                self.loop_purge_holdoffs(),
                self.loop_get_peers(),
                self.loop_find_nodes(),
                self.loop_save_data(),
            ]
        ]

        # self.listener.transport.sock.setsockopt
        def stop_all():
            for task in tasks:
                task.cancel()
            self.loop.stop()
            self.loop.close()

        self.loop.run_forever()

    cdef str format_detailed_info(self, counter):
        '''
        Prints tables of detailed information on request.
        '''

        cdef int pad_width = 1
        cdef int key_width = 35
        cdef int num_width = 15

        cdef int field_width = key_width + num_width
        cdef int padded_field_width = 2 * pad_width + field_width

        unique_prefixes = {s.split('_')[0] for s in counter if '_' in s}
        tables = {prefix: [] for prefix in unique_prefixes}

        for k, v in counter.items():
            if not '_' in k:
                continue
            prefix = k.split('_')[0]
            tables[prefix].append(
                f'{"":{pad_width}s}' +
                f'{k:.<{key_width}s}' +
                (
                    f'{v:.>{num_width},d}'
                    if prefix != 'perf'
                    else f'{v:.>{num_width}.3f}'
                ) +
                f'{"":{pad_width}s}',
            )

        for t in tables.values():
            t.sort()

        while 1 + len(tables) * (1 + padded_field_width) > TERMINAL_WIDTH and\
                len(tables) > 1:

            by_size = sorted(tables.items(), key=lambda x: len(x[1]))
            # get the smallest
            smk, smt = by_size[0]
            # and second smallest tables
            ssk, sst = by_size[1]

            # append a divider and the contents of the smallest table
            # to the second smallest
            sst.append(' ' + '-' * (field_width) + ' ')
            sst.extend(smt)

            # and delete the smallest
            tables.pop(smk)

        height = max([len(t) for t in tables.values()])
        pad_table = repeat('', height)
        end_table = repeat('', height)

        output_string = 'Detailed info:\n' + '\n'.join([
            '|'.join(row)
            for row in zip_longest(
                pad_table,
                *[tables[k] for k in sorted(tables.keys())],
                end_table,
                fillvalue=' ' * padded_field_width,
            )
        ])

        return output_string

    cdef void dump_data(self):
        cdef:
            FILE *f

        f = fopen(RT_FN, 'wb')
        fwrite(self.rt, sizeof(u8), RT_TOTAL_CONTACTS * NODEINFO_LEN, f)
        fclose(f)

        f = fopen(RT_QUAL_FN, 'wb')
        fwrite(self.rt_qual, sizeof(u8), RT_TOTAL_CONTACTS, f)
        fclose(f)

    cdef void load_data(self):
        cdef:
            FILE *f

        f = fopen(RT_FN, 'rb')
        if f:
            fread(self.rt, sizeof(u8), RT_TOTAL_CONTACTS * NODEINFO_LEN, f)
            fclose(f)

        f = fopen(RT_QUAL_FN, 'rb')
        if f:
            fread(self.rt_qual, sizeof(u8), RT_TOTAL_CONTACTS, f)
            fclose(f)

    cdef double metric_rt_fullness(self):
        cdef u64 ix, jx, kx
        cdef double acc = 0.

        for ix in range(256):
            for jx in range(256):
                for kx in range(256):
                    acc += self.rt[ix][jx][kx][0]

        return acc / (RT_TOTAL_CONTACTS * 127.5)

    cdef double metric_av_quality(self):
        cdef:
            u64 ix, jx, kx
            double acc = 0.

        for ix in range(256):
            for jx in range(256):
                for kx in range(256):
                    acc += self.rt_qual[ix][jx][kx]

        return acc / (RT_TOTAL_CONTACTS)

    cdef mstd metric_gp_rtt(self):
        cdef u64 ix
        cdef double sacc = 0.
        cdef double var = 0.
        cdef mstd result

        result.mean = 0.
        result.std = 0.

        for ix in range(RTT_BUF_LEN):
            result.mean += self._rtt_buf[ix] / RTT_BUF_LEN

        for ix in range(RTT_BUF_LEN):
            d = self._rtt_buf[ix] - result.mean
            var += d * d

        result.std = sqrt(var / (RTT_BUF_LEN - 1))
        if result.mean < 0.1:
            result.mean = 0.1

        return result

    cdef double metric_av_dkad(self):
        cdef int ix
        cdef double out = 0.

        for ix in range(DKAD_BUF_LEN):
            out += self._dkad_buf[ix]

        out /= DKAD_BUF_LEN
        return out

cdef bytes compact_peerinfo_bytes(bytes ip_addr, u16 port):
    '''
    Wrapper around compact_peerinfo to return the buffer as a bytes object
    if compact_peerinfo succeeds, and None otherwise.
    '''

    cdef u8 buf[PEERINFO_LEN]
    cdef bint success = compact_peerinfo(buf, ip_addr, port)

    if success:
        return buf[0:PEERINFO_LEN]
    else:
        return None

@cython.profile(False)
cdef inline bint compact_peerinfo(u8 *dest_buf, u8 *ip_addr, u16 port):
    '''
    MEM-UNSAFE [dest_buf]

    Returns 1 if the compact ip/port was written successfully, 0 otherwise.
    '''

    cdef u64 dx = 0  # digit counter
    cdef u64 tx = 0  # dot counter
    cdef u64 bx = 0  # index into source buffer
    cdef u64 ix = 0
    cdef u64 lb = len(ip_addr)

    if not (7 <= lb <= 15):
        return 0

    for ix in range(4):
        dest_buf[ix] = 0;

    for bx in range(lb):
        if 0x30 <= ip_addr[bx] < 0x40 and dx < 3:
            dest_buf[tx] = dest_buf[tx] * 10 + (ip_addr[bx] - 0x30)
            dx += 1
        elif ip_addr[bx] == 0x2e and tx < 3:  # '.'
            tx += 1
            dx = 0
        else:
            return 0

    # we didn't read enough dots, it's trash
    if tx < 3:
        return 0

    dest_buf[4] = port // 256
    dest_buf[5] = port % 256

    return 1

@cython.profile(False)
cdef bytes compact_ip(bytes ip_addr):
    '''
    A reduced for if inet_aton that accepts bytes instead of str.
    '''
    cdef:
        u64 ix = 0
        u64 bx = 0
        u64 tx = 0
        u64 lb = len(ip_addr)
        unsigned char buf[4]

    for ix in range(4):
        buf[ix] = 0

    for bx in range(lb):
        if ip_addr[bx] == 0x2e:
            tx += 1
            if tx > 3:
                return None
        elif 0x30 <= ip_addr[bx] < 0x40:
            buf[tx] = buf[tx] * 10 + (ip_addr[bx] - 0x30)
        else:
            return None

    return bytes(buf[0:4])

@cython.profile(False)
cdef inline tuple mk_addr_from_dht_node(dht_node_t *dhtn):
    return (inet_ntoa(dhtn.pip[:IP_LEN]).encode('ascii'), dhtn.port)

cdef bint uncompact_nodeinfo(dht_node_t *target, u8 *pnode):
    '''
    Uncompacts a packed node info string into a dht_contact structure.

    Since this structure will presumably be used to send a message, the
    sid is precomputed.
    '''

    if validate_nodeinfo(pnode):
        memcpy(target.nid, pnode,           NIH_LEN)
        memcpy(target.pip, pnode + NIH_LEN, IP_LEN)
        target.port = unpack_port(pnode + NIH_LEN + IP_LEN)
        return 1
    return 0

@cython.profile(False)
cdef inline bint validate_nodeinfo(u8 *pnode):
    return validate_peerinfo(pnode + NIH_LEN)

@cython.profile(False)
cdef inline u16 unpack_port(u8 *packed_port):
    '''
    MEM-UNSAFE packed_port[0:1]
    '''
    return packed_port[0] * 256 + packed_port[1]

# FIXME prio 4 should not need this, should extract raw token from request and
# pass it down
cdef bytes bencode_tok(bytes tok):

    cdef int lt = len(tok)
    cdef bytes slt = str(lt).encode('ascii')

    return slt + b':' + tok

@cython.profile(False)
cdef inline bint validate_peerinfo(u8 *peerinfo):
    '''MEM-UNSAFE'''
    return validate_ip_p(peerinfo) and validate_port_p(peerinfo + IP_LEN)

@cython.profile(False)
cdef bint validate_ip_p(u8 *ip):
    '''
    MEM-UNSAFE

    Checks that the `ip`, represented as a 4 byte string, is a non-reserved,
    globally routable ipv4 address.
    '''

    cdef:
        unsigned char a = ip[0]
        unsigned char b = ip[1]
        unsigned char c = ip[2]
        unsigned char d = ip[3]

    # taken from https://www.iana.org/assignments/iana-ipv4-special-registry/
    if (
            ((a & 0xf0) == 240) or # 240.0.0.0/4
            (a == 0) or
            (a == 10) or
            (a == 127) or
            (a == 100 and (b & 0xc0) == 64) or
            (a == 172 and (b & 0xf0) == 16) or
            (a == 198 and (b & 0xfe) == 18) or
            (a == 169 and b == 254) or
            (a == 192 and b == 168) or
            (a == 192 and b == 0   and c == 0) or
            (a == 192 and b == 0   and c == 2) or
            (a == 192 and b == 31  and c == 196) or
            (a == 192 and b == 51  and c == 100) or
            (a == 192 and b == 52  and c == 193) or
            (a == 192 and b == 175 and c == 48) or
            (a == 198 and b == 51  and c == 100) or
            (a == 203 and b == 0   and c == 113) or
            (a == 255 and b == 255 and c == 255 and d == 255)):

        return 0

    return 1

@cython.profile(False)
cdef inline bint validate_port(u16 port):
    # NOTE this is somewhat arbitrary, but low port dht clients are likely
    # either bullshit, or special in some undesirable way.
    return port > 1024

@cython.profile(False)
cdef inline bint validate_port_p(u8 *port):
    return validate_port(unpack_port(port))

@cython.profile(False)
cdef inline void memcpy_bytes(u8 *target, u8 *source, u64 up_to):
    memcpy(target, source, up_to)

@cython.profile(False)
cdef inline bint is_row_empty(u8 *row):
    '''
    MEM-UNSAFE
    '''
    return 0 == memcmp(row, ZERO_ROW, NODEINFO_LEN)

@cython.profile(False)
cdef inline bint is_row_equal(u8 *row, u8 *target, u64 up_to):
    '''
    MEM-UNSAFE [row[0:up_to], target[0:up_to]]
    '''
    return 0 == memcmp(row, target, up_to)

# FIXME prio 7 randint is slow, use rand
@cython.profile(False)
cdef bint check_evict(u64 cur_qual, u64 cand_qual):
    '''
    Checks if a node with quality `cur_qual` should be replaced with
    one of quality `cand_qual`.

    If `cand_qual` > `cur_qual`, evicts certainly. Else, evicts with
    probability 1 / 2 ** (cur_qual - cand_qual)
    '''

    if cand_qual >= cur_qual:
        return 1

    return randint(1 << (cur_qual - cand_qual)) == 0

# FIXME should need this since we have tok length in krpc_replies
cdef bytes mk_sid(u8 *nid):
    '''
    MEM-UNSAFE
    '''
    cdef int ix
    cdef unsigned char buf[NIH_LEN]
    cdef u8 *nsuf =\
        b'\x00\x00X\xf3Q\xca\xf1=\xd42\xae\x86j\xa9\xd6\x0c=\xe8D\x99'

    for ix in range(0, NIH_LEN):
        buf[ix] = nid[ix] ^ nsuf[ix]

    return bytes(buf[0:NIH_LEN])

@cython.profile(False)
cdef inline void mk_sid_raw(u8 *sid_buf, u8 *nid):
    '''MEM-UNSAFE'''
    cdef u64 ix
    for ix in range(0, NIH_LEN):
        sid_buf[ix] = nid[ix] ^ SID_XOR[ix]
