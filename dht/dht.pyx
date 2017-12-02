# cython: language_level=3, profile=True, wraparound=False
'''
Stateless DHT scraper.
'''
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
from socket import inet_ntoa, inet_aton
from time import time, monotonic

import numpy as np
from numpy.random import bytes as rbytes, random, randint
from uvloop import new_event_loop as new_uv_loop

from vnv.util import save_pickle, load_pickle
from vnv.log import get_logger

cimport cython
from libc.stdint cimport uint8_t as u8, uint16_t as u16, uint64_t as u64
from libc.stdint cimport int8_t as i8, int64_t as i64
from libc.stdio cimport FILE, fopen, fwrite, fclose, fread, sprintf
from libc.string cimport memcmp, memset, memcpy
from libc.math cimport sqrt, fmin, fmax

# internal
from dht.util cimport LRUCache, sim_kad_apx, format_uptime
from dht.bdecode_st cimport bd_status, parsed_msg, krpc_bdecode, print_parsed_msg
from dht.bdecode_st cimport bd_status_names, krpc_msg_type

include "dht_h.pxi"

class BadState(Exception): pass

# from dht.bencode cimport bdecode_d

LOG = get_logger('dht')
sys.tracebacklimit = 1000

# net: sockets
DHT_LPORT = int(sys.argv[1])
if len(sys.argv) > 2:
    LOG.setLevel(int(sys.argv[2]))

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

    struct dht_node:
        # set by unpacking functions; should discard this node at a good time
        bint valid
        # computed sid
        u8 sid[IH_LEN]
        # krpc node info
        u8 nid[IH_LEN]
        # FIXME @raw_uv: should not need extensive-form ip
        u8 ip[IP_LEN]
        u16 port

    u8 ZERO_ROW[NODEINFO_LEN]

memset(ZERO_ROW, 0, NODEINFO_LEN)

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
            str   ctl_key):

        '''
        Ctl byte should be nid-constant but random over nids.

        Used to selectively drop messages to throttle. Lowest byte is a good
        choice.
        '''

        if prio == 0 and self._do_drop:
            self.scraper.cnt['tx_msg_buffer_overflow'] += 1
        elif prio == 1 or ctl_byte <= 255 * self.scraper.ctl_reply_rate:
            self.scraper.cnt['tx_msg'] += 1
            self.scraper.cnt[ctl_key] += 1
            self.transport.sendto(msg, addr)
        else:
            self.scraper.cnt['tx_msg_throttle_drop'] += 1

    cpdef void connection_made(self, object transport):
        LOG.info('Connection made.')
        self.transport = transport

    cpdef void error_received(self, object exc):
        self.scraper.cnt['rx_err_' + exc.__class__.__name__] += 1

    cpdef void datagram_received(self, bytes data, tuple saddr):
        try:
            self.scraper.handle_msg(data, saddr)
            self.scraper.cnt['rx_msg'] += 1
        except OSError as e:
            self.scraper.cnt['rx_err_OSError'] += 1
        except Exception as e:
            self.scraper.cnt['err_rx_' + e.__class__.__name__] += 1
            LOG.error(f'Unhandled error in handle_raw_msg\n{trc.format_exc()}')

    cpdef void pause_writing(self):
        self._do_drop = 1

    cpdef void resume_writing(self):
        self._do_drop = 0

cdef class DHTScraper:

    cdef:
        # data objects
        object naked_ihashes
        dict info_in_flight
        unsigned char rt[256][256][RT_CONTACTS_PER_BIN][NODEINFO_LEN]
        unsigned char rt_qual[256][256][RT_CONTACTS_PER_BIN]
        object cnt

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

        # internal control variables
        float _start_time
        object _disp_cnt
        object _ctl_cnt
        u64 _info_iter
        double _info_mark
        double _control_mark
        double _rtt_buf[RTT_BUF_LEN]
        u64 _rtt_buf_ix

        # caches and pools for I/O ops
        list _db_row_pool
        dict _db_desc_pool
        set _db_new_ih_staging

    def __cinit__(self):
        # == DHT ==
        # plain list of known infohashes
        self.naked_ihashes = deque([], maxlen=MAX_IHASHES)  # type: ignore

        # info hashes actively being identified
        # indexed by associated nids; this is onto
        self.info_in_flight = {}

        # counter for various statistics of interest, reset every report cycle
        self.cnt = Counter()

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
        self._disp_cnt = self.cnt.copy()
        self._ctl_cnt = self.cnt.copy()
        self._info_iter = 0
        self._info_mark = 0.
        self._control_mark = 0.

        for i in range(RTT_BUF_LEN):
            self._rtt_buf[i] = 0.2

        self._db_row_pool = []
        self._db_desc_pool = {}
        self._db_new_ih_staging = set()

        # control variables
        self.ctl_ifl_target = BASE_IFL_TARGET
        self.ctl_ihash_discard = BASE_IHASH_DISCARD
        self.ctl_ihash_refresh = BASE_IHASH_REFRESH
        self.ctl_timeout = BASE_GP_TIMEOUT
        self.ctl_ping_rate = BASE_PING_RATE
        self.ctl_reply_rate = 1.0

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
            u8 cx = (nid[2] & 0xe0) >> 5

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
            u8 cx = (nid[2] & 0xe0) >> 5

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

        memcpy(sender_pnode, krpc.nid, NID_LEN)

        good_addr = compact_peerinfo(sender_pnode + NID_LEN, addr[0], addr[1])
        if not good_addr:
            self.cnt['rt_replace_bad_node'] += 1
            return RT_REP_INVALID_NODE

        rep_status = self.rt_random_replace_contact(sender_pnode, base_qual)

        if rep_status == RT_REP_SUCCESS:
            self.cnt['rt_replace_accept'] += 1
        elif rep_status == RT_REP_NO_EVICT:
            self.cnt['rt_replace_reject'] += 1
        else:
            self.cnt['rt_replace_bad_node'] += 1

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
        if not is_row_equal(nid, cur_nodeinfo, NID_LEN):
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

        if not is_row_empty(neighbor_cell):
            return neighbor_cell

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
            ax = jx // (RT_CONTACTS_PER_BIN * 256)
            bx = (jx // RT_CONTACTS_PER_BIN) % 256
            cx = jx % RT_CONTACTS_PER_BIN
            if validate_nodeinfo(self.rt[ax][bx][cx]):
                return self.rt[ax][bx][cx]
            elif not is_row_empty(self.rt[ax][bx][cx]):
                memset(self.rt[ax][bx][cx], 0, NODEINFO_LEN)
                self.rt_qual[ax][bx][cx] = MIN_QUAL
                self.cnt['rt_scrubbed_bad_contact'] += 1

        self.cnt['err_rt_no_contacts'] += 1
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

        self.cnt['db_update_peers'] += 1

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

            self.cnt['db_rows_inserted'] += len(self._db_row_pool)
            self._db_row_pool.clear()

    cdef void handle_new_nodes(self, u8 *pnodes, u64 n_nodes):
        '''
        Generic processor for all new found nodes.

        Sends out pings to qualifying nodes to referesh the routing table.
        '''

        cdef u64 offset, status_code
        cdef bint did_replace
        cdef dht_node ping_contact
        cdef u8 bitmask = 0
        cdef u8 zx

        for offset in range(0, NODEINFO_LEN * n_nodes, NODEINFO_LEN):

            # bitmask keeps track of which cx indices we have inserted already
            # this call; this is sufficient since most calls share ax and bx
            zx = 1 << ((pnodes[offset + 2] & 0xe0) >> 5)
            if zx & bitmask:
                self.cnt['rt_newnode_drop_repeat'] += 1
                continue

            elif random() > self.ctl_ping_rate:
                self.cnt['rt_newnode_drop_unlucky'] += 1
                continue

            bitmask |= zx

            uncompact_nodeinfo(&ping_contact, pnodes + offset)
            self.send_q_pg(&ping_contact)

            self.cnt['rt_newnode_ping'] += 1

    cdef void handle_gp_nodes(self, parsed_msg *krpc, tuple saddr):
        '''
        Processes nodes received in a get_peers reply.

        Checks whether the we have an infohash tied to the reply, whether
        the nodes received are suitable, and if yes, follows up with the
        next node.
        '''

        cdef dht_node followup_contact
        cdef u8 cur_sim, best_sim

        old_nid = krpc.nid[0:IH_LEN]
        maybe_ih = self.info_in_flight.get(old_nid)

        if maybe_ih == 1:
            # we matched peers for this, don't need nodes
            return

        if maybe_ih is None:
            self.cnt['bm_gp_nodes_unmatched'] += 1
            return

        del self.info_in_flight[old_nid]

        self._rtt_buf[self._rtt_buf_ix] = monotonic() - maybe_ih[1]
        self._rtt_buf_ix = (self._rtt_buf_ix + 1) % RTT_BUF_LEN

        target_ih = maybe_ih[0]

        # NOTE: experiments have shown that selecting the best contact
        # does not better than just picking the first
        uncompact_nodeinfo(&followup_contact, krpc.nodes)
        
        if not followup_contact.valid:
            self.cnt['bm_gp_node_invalid'] += 1
            self.rt_adj_quality(old_nid, -2)
            return

        cur_sim = sim_kad_apx(followup_contact.nid, target_ih)
        best_sim = sim_kad_apx(old_nid, target_ih)

        if cur_sim <= best_sim:
            self.cnt['bm_gp_node_too_far'] += 1
            self.rt_adj_quality(old_nid, -2)
            return

        self.cnt['ih_got_good_next_hop'] += 1
        self.rt_adj_quality(old_nid, 3)

        self.send_q_gp(target_ih, &followup_contact, 1)
        # XXX bytes conversion
        self.info_in_flight[followup_contact.nid[0:NID_LEN]] =\
            (target_ih, monotonic())


    cdef void handle_new_peers(self, u8 *nid, u8 *peers, u64 n_peers):

        cdef list good_peers = []
        cdef u64 offset
        cdef u16 port
        cdef object maybe_ih
        cdef bint got_bad_peer = 0

        # FIXME
        maybe_ih = self.info_in_flight.get(nid[0:IH_LEN])

        if maybe_ih is not None and maybe_ih != 1:

            self.cnt['ih_matched_peers'] += 1
            # NOTE: mark for the node parse that we matched
            self.info_in_flight[nid[0:IH_LEN]] = 1

            for offset in range(0, n_peers * PEERINFO_LEN, PEERINFO_LEN):

                if not validate_peerinfo(peers + offset):
                    got_bad_peer = 1
                    continue

                good_peers.append(peers[offset:offset + 6])

        else:
            self.cnt['bm_unmatched_peers'] += 1
            return

        ih = maybe_ih[0]

        if len(good_peers) == 0:
            self.cnt['bm_no_good_peers'] += 1
            self.rt_adj_quality(nid, -3)
            return

        elif got_bad_peer:
            self.cnt['bm_some_bad_peers'] += 1
            self.rt_adj_quality(nid, -1)

        self.db_update_peers(ih, good_peers)

    # XXX get rid of tuple conversion
    cdef void handle_msg(self, bytes d, tuple saddr):

        cdef parsed_msg krpc
        cdef bd_status status
        cdef u64 replace_status
        cdef u16 ap_port
        cdef str decoded_name
        cdef bytes ih, raw_ap_name

        saddr = (saddr[0].encode('ascii'), saddr[1])

        status = krpc_bdecode(d, &krpc)
        self.cnt[f'st_{bd_status_names[status]}'] += 1

        if status != bd_status.NO_ERROR:
            IF BD_TRACE:
                if status == bd_status.FALLTHROUGH:
                    print('')
                    print(d)
                    print('\n'.join(g_trace))
            return

        if krpc.method == krpc_msg_type.Q_AP:
            self.cnt['rx_q_ap'] += 1

            replace_status = self.rt_add_sender_as_contact(&krpc, saddr, 3)

            if krpc.token_len != 1 or krpc.token[0] != TOKEN:
                self.cnt['bm_ap_bad_token'] += 1
                return

            if krpc.ap_implied_port:
                ap_port = <u16> saddr[1]
            else:
                ap_port = krpc.ap_port

            if krpc.ap_name_len > 0:

                raw_ap_name = krpc.ap_name[0:krpc.ap_name_len]

                try:
                    # XXX faster utf8 checking
                    decoded_name = raw_ap_name.decode('utf-8')
                except UnicodeDecodeError:
                    self.cnt['bm_ap_bad_name'] += 1
                    return

                ih = krpc.ih[0:20]

                    # FIXME: descriptions
                self.db_update_peers(ih, [compact_peerinfo_bytes(saddr[0], ap_port)])
                self._db_desc_pool[ih] = raw_ap_name

            self.send_r_pg(krpc.nid, krpc.tok[0:krpc.tok_len], saddr, 1)

        elif krpc.method == krpc_msg_type.Q_FN:
            self.cnt['rx_q_fn'] += 1
            self.rt_add_sender_as_contact(&krpc, saddr, 2)

            pnode = self.rt_get_valid_neighbor_contact(krpc.target[0:IH_LEN])
            self.send_r_fn(pnode, krpc.nid, krpc.tok[0:krpc.tok_len], saddr)

        elif krpc.method == krpc_msg_type.Q_GP:
            self.cnt['rx_q_gp'] += 1
            self.rt_add_sender_as_contact(&krpc, saddr, 2)
            # FIXME this check is too slow, need to move to rolling bloom
            # filters

            new_ih = krpc.ih[0:IH_LEN]
            self._db_new_ih_staging.add(new_ih)

            pnode = self.rt_get_valid_neighbor_contact(krpc.ih)
            if pnode != NULL:
                self.send_r_gp(
                    pnode, krpc.nid, krpc.tok[0:krpc.tok_len], saddr)

        elif krpc.method == krpc_msg_type.Q_PG:
            self.cnt['rx_q_pg'] += 1
            self.rt_add_sender_as_contact(&krpc, saddr, 1)

            self.send_r_pg(krpc.nid, krpc.tok[0:krpc.tok_len], saddr, 0)

        elif krpc.method == krpc_msg_type.R_GP:
            self.cnt['rx_r_gp'] += 1

            if krpc.n_peers > 0:
                self.cnt['rx_r_gp_v'] += 1
                self.handle_new_peers(krpc.nid, krpc.peers, krpc.n_peers)

            # NOTE yes, ignore nodes from responses with peers
            elif krpc.n_nodes > 0:
                self.cnt['rx_r_gp_n'] += 1
                self.handle_new_nodes(krpc.nodes, krpc.n_nodes)
                self.handle_gp_nodes(&krpc, saddr)

            elif krpc.n_peers + krpc.n_nodes == 0:
                IF BD_TRACE:
                        print('EMPTY PEERS IN R_GP')
                        print(d)
                        print('\n'.join(g_trace))
                        return
                self.cnt['err_r_gp_empty_peers'] += 1

        elif krpc.method == krpc_msg_type.R_FN:
            self.cnt['rx_r_fn'] += 1
            if krpc.n_nodes == 0:
                IF BD_TRACE:
                    print('EMPTY NODES IN R_FN')
                    print(d)
                    print('\n'.join(g_trace))
                    return
                self.cnt['err_r_fn_empty_nodes'] += 1

            # these nodes are usually close, so set only one
            self.handle_new_nodes(krpc.nodes, 1)

        elif krpc.method == krpc_msg_type.R_PG:
            self.rt_add_sender_as_contact(&krpc, saddr, 2)
            self.cnt['rx_r_pg'] += 1

        else:
            IF BD_TRACE:
                print('HANDLE FALLTHROUGH')
                print(d)
                print('\n'.join(g_trace))
            self.cnt['err_handle_fallthrough'] += 1

    # FIXME implement
    cdef void send_sample_infohashes(self, bytes nid, tuple addr):
        pass

    cdef void send_q_fn_random(self, dht_node *dest):
        cdef bytearray random_target = bytearray(rbytes(20))
        random_target[0] = dest.nid[0]
        random_target[1] = dest.nid[1]
        self.send_q_fn(rbytes(IH_LEN), dest)

    cdef void send_q_fn(self, u8 *target, dht_node *dest):
        '''
        Solicit a new random node based on our current self id and the current
        state
        '''
        cdef u8 msg_buf[Q_FN_LEN]

        memcpy(msg_buf,                      Q_FN_PROTO, Q_FN_LEN)
        memcpy(msg_buf + Q_FN_TARGET_OFFSET, target,     NID_LEN)
        mk_sid_raw(msg_buf + Q_FN_SID_OFFSET, dest.nid)

        # XXX bytes conversion
        self.listener.send_msg(
            msg_buf[:Q_FN_LEN], node_to_addr_tup(dest),
            0, dest.nid[NID_LEN - 1],
            'tx_q_fn',
        )

    cdef void send_q_gp(self, u8 *ih, dht_node *dest, u64 prio):
        '''
        Send get_peers query.
        '''
        cdef u8 msg_buf[Q_GP_LEN]

        memcpy(msg_buf,                    Q_GP_PROTO, Q_GP_LEN)
        memcpy(msg_buf + Q_GP_IH_OFFSET,     ih,         IH_LEN)
        mk_sid_raw(msg_buf + Q_GP_SID_OFFSET, dest.nid)

        # XXX bytes conversion
        self.listener.send_msg(
            msg_buf[:Q_GP_LEN], node_to_addr_tup(dest),
            prio, dest.nid[NID_LEN - 1],
            'tx_q_gp',
        )

    cdef void send_q_pg(self, dht_node *dest):
        cdef u8 msg_buf[Q_PG_LEN]

        memcpy(msg_buf, Q_PG_PROTO, Q_PG_LEN)
        mk_sid_raw(msg_buf + Q_PG_SID_OFFSET, dest.nid)

        # XXX bytes conversion
        self.listener.send_msg(
            msg_buf[:Q_PG_LEN], node_to_addr_tup(dest),
            0,
            dest.nid[NID_LEN - 1],
            'tx_q_pg',
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
            nid[NID_LEN - 1],
            'tx_r_fn',
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
            nid[NID_LEN - 1],
            'tx_r_pg',
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
            nid[NID_LEN - 1],
            'tx_r_gp',
        )

    @aio_loop_method(GP_SLEEP)
    def loop_get_peers(self):

        cdef dht_node gp_contact
        cdef u8 *pnode
        cdef bytes bnid, ih

        while len(self.info_in_flight) < self.ctl_ifl_target:
            try:
                ih = self.naked_ihashes.pop()
            except IndexError:
                self.cnt['ih_raw_ihs_exhausted'] += 1

                pnode = self.rt_get_random_valid_node()
                if pnode != NULL:
                    uncompact_nodeinfo(&gp_contact, pnode)
                    self.send_q_fn_random(&gp_contact)

                return

            # try to get a node close to the infohash
            pnode = self.rt_get_valid_neighbor_contact(ih)
            if pnode != NULL:

                uncompact_nodeinfo(&gp_contact, pnode)
                bnid = gp_contact.nid[0:NID_LEN]

                if bnid in self.info_in_flight:
                    self.cnt['ih_node_already_in_ifl'] += 1
                else:
                    self.send_q_gp(ih, &gp_contact, 1)
                    self.info_in_flight[bnid] = (ih, monotonic())
                    self.cnt['ih_naked_ih_put_in_ifl'] += 1

                continue

            self.cnt['ih_no_good_neighbors'] += 1
            pnode = self.rt_get_random_valid_node()
            if pnode != NULL:
                uncompact_nodeinfo(&gp_contact, pnode)
                self.send_q_fn(ih, &gp_contact)

    @aio_loop_method(FP_SLEEP)
    def loop_find_nodes(self):
        '''
        Send out find_node randomly.

        The goal is to inject ourselves into as many nodes' routing tables
        as possible, and to refresh the routing table.
        '''

        cdef dht_node fn_contact
        cdef u8 *pnode

        pnode = self.rt_get_random_valid_node()
        if pnode != NULL:
            uncompact_nodeinfo(&fn_contact, pnode)
            self.send_q_fn_random(&fn_contact)

    @aio_loop_method(PURGE_SLEEP, init_sleep=5.0)
    def loop_purge_ifl(self):
        '''
        Purges the info_in_flight tables of requests that have timed out
        or been moved on to the next hop.
        '''

        timeout_thresh = monotonic() - self.ctl_timeout

        bad_nids = {
            k for k, v in self.info_in_flight.items()
            if (v is None) or (v == 1) or (v[1] < timeout_thresh)
        }

        for bad_nid in bad_nids:
            try:
                maybe_ih = self.info_in_flight[bad_nid]
                if maybe_ih is not None and maybe_ih != 1:
                    ih = maybe_ih[0]
                    if random() > self.ctl_ihash_discard:
                        self.naked_ihashes.appendleft(ih)

                # minor penalty for not responding - not as bad as
                # giving us bogus info of various kinds.
                self.rt_adj_quality(bad_nid, -1)

                del self.info_in_flight[bad_nid]
                self.cnt['ih_stale_ifl_purged'] += 1

            except KeyError:
                self.cnt['err_to_purge_disappeared'] += 1

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
            # '''
            # INSERT INTO `metainfo` (`info_hash`, `description`)
            # VALUE (%(ih)s, %(desc)s)
            # ON DUPLICATE KEY UPDATE SET `description`=%(desc)s
            # ''',
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

        cdef list staged_ihs = sorted(
            self._db_new_ih_staging - self.info_in_flight.keys()
        )
        self._db_new_ih_staging.clear()

        self.cnt['ih_staged_all'] += len(staged_ihs)

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
            staged_ihs,
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

        staged_ihs = [row[0] for row in self._db.fetchall()]
        self.cnt['ih_staged_new'] += len(staged_ihs)
        self.naked_ihashes.extendleft(staged_ihs)
            
    @aio_loop_method(BOOTSTRAP_SLEEP, init_sleep=BOOTSTRAP_SLEEP)
    def loop_boostrap(self):
        cdef dht_node new_contact

        if self.metric_rt_fullness() < 0.01:
            for addr in BOOTSTRAP:
                # FIXME this is a lot of useless conversion an deconversion
                # harmless in low freq. bootstrap, but still...
                memcpy_bytes(new_contact.nid, rbytes(NID_LEN), NID_LEN)
                memcpy_bytes(new_contact.ip, inet_aton(addr[0]), IP_LEN)
                new_contact.port = addr[1]

                if validate_ip_p(new_contact.ip) and\
                        validate_port(new_contact.port):
                    new_contact.valid = 1
                    self.send_q_fn_random(&new_contact)
                else:
                    self.cnt['err_bootstrap_bad_contact'] += 1

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
        self._control_mark = t

        dcnt = self.cnt - self._ctl_cnt
        self._ctl_cnt = self.cnt.copy()

        cdef double gpps = dcnt['rx_q_gp'] / dt

        self.ctl_reply_rate = max(0.0, min(
                1.0,
                1 - (gpps - GPPS_RX_TARGET) / (GPPS_RX_MAX - GPPS_RX_TARGET)
            ))

        self.ctl_ihash_discard = len(self.naked_ihashes) / MAX_IHASHES
        self.ctl_ping_rate = (1 - self.ctl_ihash_discard) / 10

        rtt_stat = self.metric_gp_rtt()
        self.ctl_timeout = max(0.1, rtt_stat.mean + 3 * rtt_stat.std)

    @aio_loop_method(INFO_SLEEP, init_sleep=INFO_SLEEP)
    def loop_info(self):

        cdef double t = monotonic()
        cdef double dt = t - self._info_mark

        self._info_mark = t

        raw_dcnt = self.cnt - self._disp_cnt
        self._disp_cnt = self.cnt.copy()

        # get peers response rate
        gprr = min(1.0, raw_dcnt["rx_r_gp"] / (raw_dcnt["tx_q_gp"] + 1))
        # values to nodes ratio (in gp_response)
        vnr = (raw_dcnt["rx_r_gp_v"] + 1) / (raw_dcnt["rx_r_gp_n"] + 1)
        # db accept rate (number of new infohashes not in db already)
        newih, allih = raw_dcnt["ih_staged_new"] + 1, raw_dcnt["ih_staged_all"] + 1
        newr = newih / allih

        # get peers round trip time
        rtt = self.metric_gp_rtt()
        
        # routing table replacement rate
        rts = raw_dcnt["rt_replace_accept"] + 1
        rtf = raw_dcnt["rt_replace_reject"] + 1
        rtx = raw_dcnt["rt_replace_bad_node"] + 1
        rt_rr  = rts / (rts + rtf + rtx)

        newr = (raw_dcnt["ih_staged_new"] + 1) / (raw_dcnt["ih_staged_all"] + 1)

        x = Counter()
        x.update({k: int(v / dt) for k, v in raw_dcnt.items()})

        self.cnt['perf_rtrr'] = rt_rr
        self.cnt['perf_rr_gp'] = gprr
        self.cnt['perf_rr_fn'] =\
            min(1.0, (raw_dcnt['rx_r_fn'] + 1) / (raw_dcnt['tx_q_fn'] + 1))
        self.cnt['perf_rr_pg'] =\
            min(1.0, (raw_dcnt['rx_r_pg'] + 1) / (raw_dcnt['tx_q_pg'] + 1))

        self.cnt['perf_rr_tot'] = min(
            1.0,
            (
                raw_dcnt['rx_r_fn'] +
                raw_dcnt['rx_r_pg'] +
                raw_dcnt['rx_r_gp'] + 1
            ) / (
                raw_dcnt['tx_q_fn'] +
                raw_dcnt['tx_q_pg'] +
                raw_dcnt['tx_q_gp'] + 1
            )
        )

        self.cnt['perf_rtt_ms'] = 1000. * rtt.mean
        self.cnt['perf_rtt_ms_std'] = 1000. * rtt.std

        self.cnt['perf_db_newr'] = newr

        info = (
            f'{format_uptime(int(monotonic() - self._start_time)):>9s} | '  # len 11
            f'{x["rx_q_pg"]:>5d} '  # len 6
            f'{x["rx_q_fn"]:>5d} {x["rx_r_fn"]:>5d} '  # len 12
            f'{x["rx_q_gp"]:>5d} '  # len 12
            f'{x["rx_r_gp_v"]:>5d} {x["rx_r_gp_n"]:>5d} '
            f'{x["rx_q_ap"]:>5d} | '  # len 11
            f'{x["tx_q_fn"]:>5d} {x["tx_r_fn"]:>5d} {x["tx_q_gp"]:>5d} '  # len 18
            f'{x["tx_r_gp"]:>5d} {x["tx_q_pg"]:>5d} '  # len 12
            f'{x["tx_r_pg"]:>5d} | '  # len 6
            f'{x["db_update_peers"]:>4d} {x["db_rows_inserted"]:>5d} ' #  len 10
            f'{x["ih_staged_all"]:>5d} {newr:5.3f} | '  # len 14
            f'{gprr:>4.2f}({self.ctl_reply_rate:>4.2f}) ' # len 11
            f'{self.ctl_ifl_target:>4d} {vnr:4.2f} '  # len 15
            f'{int(1000 * rtt.mean):>3d}±{int(1000 * rtt.std):>3d} | '  # len 10
            f'{self.metric_av_quality():>4.2f} {rt_rr:4.2f} | '  # len 11
        )

        header_high = (
            '--STATS---| '
            '------------------ RX ------------------- | '
            '---------------- TX --------------- | '
            '--------- DB -------- | '
            '------------ PERF ---------- | '
            '--- RT -- |'
        )

        header_low = (
            '  uptime  | '
            ' ping '
            '   fn  r_fn '
            '   gp '
            'gp_rv gp_rn '
            '   ap | '
            '   fn  r_fn    gp '
            ' gp_r    pg  pg_r | '
            'dbup  dbnr '
            '  stg  newr | '
            'gprr (own) '
            'load  vnr '
            'rtt(ms) | '
            'qual rtrr |'
        )

        if not self._info_iter:
            LOG.info(header_high)
            LOG.info(header_low)

        LOG.info(info)
        self._info_iter = (self._info_iter + 1) % INFO_HEADER_EVERY

        with open(INFO_FILE, 'w') as f:
            f.write(self.format_detailed_info())

    def run(self):
        # XXX fixme cython time jitters all over the place on startup,
        # this can be later than the first time call in info(), causing
        # stupidity
        self._start_time = monotonic()
        self._info_mark = self._control_mark = monotonic()

        self.load_data()

        run_listener = self.loop.create_datagram_endpoint(
            lambda: self.listener, local_addr=('0.0.0.0', DHT_LPORT)
        )

        # order matters here
        tasks = [
            aio.ensure_future(task_loop, loop=self.loop) for task_loop in [
                run_listener,
                self.loop_info(),
                self.loop_control(),
                self.loop_boostrap(),
                self.loop_stage_new_ihashes(),
                self.loop_dump_descs(),
                self.loop_purge_ifl(),
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

    cdef str format_detailed_info(self):
        '''
        Prints tables of detailed information on request.
        '''

        cdef int pad_width = 1
        cdef int key_width = 35
        cdef int num_width = 15

        cdef int field_width = key_width + num_width
        cdef int padded_field_width = 2 * pad_width + field_width

        unique_prefixes = {s.split('_')[0] for s in self.cnt if '_' in s}
        tables = {prefix: [] for prefix in unique_prefixes}

        for k, v in self.cnt.items():
            if not '_' in k:
                continue
            prefix = k.split('_')[0]
            tables[prefix].append(
                f'{"":{pad_width}s}' +
                f'{k:.<{key_width}s}' + 
                (
                    f'{v:.>{num_width},d}'
                    if prefix != 'perf'
                    else f'{v:.>{num_width}.2f}'
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
        fwrite(
            self.rt, sizeof(u8),
            256 * 256 * RT_CONTACTS_PER_BIN * NODEINFO_LEN, f,
        )
        fclose(f)

        f = fopen(RT_QUAL_FN, 'wb')
        fwrite(self.rt_qual, sizeof(u8), 256 * 256 * RT_CONTACTS_PER_BIN, f)
        fclose(f)

    cdef void load_data(self):
        cdef:
            FILE *f

        f = fopen(RT_FN, 'rb')
        if f:
            fread(
                self.rt, sizeof(u8),
                256 * 256 * RT_CONTACTS_PER_BIN * NODEINFO_LEN,
                f,
            )
            fclose(f)

        f = fopen(RT_QUAL_FN, 'rb')
        if f:
            fread(self.rt_qual, sizeof(u8), 256 * 256 * RT_CONTACTS_PER_BIN, f)
            fclose(f)

    cdef double metric_rt_fullness(self):
        cdef u64 ix, jx, kx
        cdef double acc = 0.

        for ix in range(256):
            for jx in range(256):
                for kx in range(RT_CONTACTS_PER_BIN):
                    acc += self.rt[ix][jx][kx][0] / 128.

        return acc / (256 * 256 * RT_CONTACTS_PER_BIN)

    cdef double metric_av_quality(self):
        cdef:
            u64 ix, jx, kx
            double acc = 0.

        for ix in range(256):
            for jx in range(256):
                for kx in range(RT_CONTACTS_PER_BIN):
                    acc += self.rt_qual[ix][jx][kx]

        return acc / (256 * 256 * RT_CONTACTS_PER_BIN)

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

cdef inline void mk_sid_raw(u8 *sid_buf, u8 *nid):
    '''MEM-UNSAFE'''
    cdef u64 ix
    for ix in range(0, IH_LEN):
        sid_buf[ix] = nid[ix] ^ SID_XOR[ix]

# FIXME should need this since we have tok length in krpc_replies
cdef bytes mk_sid(u8 *nid):
    '''
    MEM-UNSAFE
    '''
    cdef int ix
    cdef unsigned char buf[IH_LEN]
    cdef u8 *nsuf =\
        b'\x00\x00X\xf3Q\xca\xf1=\xd42\xae\x86j\xa9\xd6\x0c=\xe8D\x99'

    for ix in range(0, IH_LEN):
        buf[ix] = nid[ix] ^ nsuf[ix]

    return bytes(buf[0:IH_LEN])

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
cdef inline bint compact_peerinfo(u8 *dest_buf, bytes ip_addr, u16 port):
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

# FIXME don't really need this, can use raw nodeinfo buffers
# would get rid of a lot of cruft as well
cdef void uncompact_nodeinfo(dht_node *target, u8 *pnode):
    '''
    Uncompacts a packed node info string into a dht_contact structure.

    Since this structure will presumably be used to send a message, the
    sid is precomputed.
    '''

    target.valid = 0

    if validate_peerinfo(pnode + NID_LEN):
        memcpy(target.nid, pnode, NID_LEN)
        memcpy(target.ip, pnode + NID_LEN, IP_LEN)
        target.port = unpack_port(pnode + NID_LEN + IP_LEN)
        target.valid = 1

cdef tuple node_to_addr_tup(dht_node *node):
    return (inet_ntoa(node.ip[:IP_LEN]).encode('ascii'), node.port)

@cython.profile(False)
cdef inline u16 unpack_port(u8 *packed_port):
    '''MEM-UNSAFE'''
    return packed_port[0] * 256 + packed_port[1]

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

# FIXME prio 4 should not need this, should extract raw token from request and
# pass it down
cdef bytes bencode_tok(bytes tok):

    cdef int lt = len(tok)
    cdef bytes slt = str(lt).encode('ascii')

    return slt + b':' + tok

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
cdef inline bint validate_peerinfo(u8 *peerinfo):
    '''MEM-UNSAFE'''
    return validate_ip_p(peerinfo) and validate_port_p(peerinfo + IP_LEN)

@cython.profile(False)
cdef inline bint validate_nodeinfo(u8 *nodeinfo):
    '''MEM-UNSAFE'''
    return validate_peerinfo(nodeinfo + NID_LEN)

cdef inline void memcpy_bytes(u8 *target, u8 *source, u64 up_to):
    memcpy(target, source, up_to)
