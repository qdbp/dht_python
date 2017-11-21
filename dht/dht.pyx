# cython: profile=True
'''
Stateless DHT scraper.
'''
from atexit import register as atxreg
import asyncio as aio
from asyncio import sleep as asleep
from collections import Counter, deque
from functools import lru_cache, wraps
from itertools import zip_longest, repeat
import signal as sig
import sys
import sqlite3 as sql
import traceback as trc
import pickle
from socket import inet_ntoa
from time import time, monotonic

import numpy as np
from numpy.random import bytes as rbytes, random, randint
from uvloop import new_event_loop as new_uv_loop

# internal
from dht.bencode import BdecodeError
from dht.bencode cimport bdecode
from dht.bdecode_st cimport bdx_error, parsed_msg, krpc_bdecode, print_parsed_msg
from dht.bdecode_st cimport g_trace, bdx_names

from vnv.util import save_pickle, load_pickle
from vnv.log import get_logger

cimport cython
from libc.stdint cimport uint8_t as u8, uint16_t as u16, uint64_t as u64
from libc.stdio cimport FILE, fopen, fwrite, fclose, fread, sprintf
from libc.string cimport memcmp, memset, memcpy
from libc.math cimport sqrt, fmin, fmax

from dht.util cimport LRUCache
# from dht.bencode cimport bdecode_d

LOG = get_logger('dht')

# net: sockets
DHT_LPORT = int(sys.argv[1])
if len(sys.argv) > 2:
    LOG.setLevel(int(sys.argv[2]))

DEF FULL_TOK = b'1:t1:\x77'
DEF TOKEN = b'\x88'

# dht: bootstrap, router.bittorrent.com
BOOTSTRAP = [('67.215.246.10', 6881)]

# info loop parameters
DEF INFO_HEADER_EVERY = 10
DEF TERMINAL_WIDTH = 160

# loop granularities
DEF FP_SLEEP = 0.05
DEF GP_SLEEP = 0.01
DEF PURGE_SLEEP = 0.05
DEF BOOTSTRAP_SLEEP = 1.0
DEF CONTROL_SLEEP = 1.0
DEF INFO_SLEEP = 5.0
DEF SAVE_SLEEP = 60.0

# cache sizes and flush intervals
DEF MAX_NODES = 25000
DEF MAX_IHASHES = 25000
DEF RTT_BUF_LEN = 1000
DEF ROW_POOL_MAXLEN = 1000
DEF DB_LRU_MAXSIZE = 25000000

DEF GP_QS_PER_IH = 2
DEF FP_THRESH = MAX_NODES // 2
DEF FP_NUMBER = 5

DEF GPRR_FLOOR = 0.30
DEF GPRR_CEIL = 0.40
DEF MIN_IFL_TARGET = 10
DEF BASE_IFL_TARGET = 500
DEF BASE_IHASH_DISCARD = 0.25
DEF BASE_IHASH_REFRESH = 0.03
DEF BASE_PING_RATE = 0.05
DEF BASE_IHASH_REFRESH_AGE = 3600 * 24
DEF BASE_GP_TIMEOUT = 1.0

DEF DB_FN = b'./data/dht.db'
DEF RT_FN = b'./data/rt.dat'
DEF RT_QUAL_FN = b'./data/rt_qual.dat'

# rt constants
DEF RT_CONTACTS_PER_BIN = 8
DEF IH_LEN = 20
DEF PEERINFO_LEN = 6
DEF NODEINFO_LEN = IH_LEN + PEERINFO_LEN
DEF MIN_QUAL = 0
DEF MAX_QUAL = 7

DEF MSG_MAX_LEN = 600  # arbitrary, but gives generous leeway
DEF MSG_MIN_LEN = 45  # minimum valid message length with 0-length token

def in_data(fn):
    return './data/' + fn

# === global cdefs ===
cdef:
    struct mstd:
        double mean
        double std

    u8 ZERO_ROW[NODEINFO_LEN]

    struct parsed_msg:
        # null-terminated token
        unsigned char tok[32]
        # token length, for convenience
        u64 tok_len
        # self explanatory
        unsigned char nid[IH_LEN]
        unsigned char ih[IH_LEN]
        unsigned char target[IH_LEN]
        # method used, one of the METHOD_ constants
        u64 method
        # nodes, not all will be set
        unsigned char nodes[NODEINFO_LEN * 8]
        # number of nodes set
        u64 num_nodes
        # gp token
        unsigned char token[32]
        # token length
        u64 token_len
        # peers, not all will be set
        unsigned char peers[PEERINFO_LEN * 8]
        # number of peers set
        u64 peers_len
        # if implied port is set
        bint implied_port

    dict g_bd_dict = {k: set() for k in range(MSG_MIN_LEN, MSG_MAX_LEN + 1)}

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

    cdef void send_msg(self, bytes msg, tuple addr, u64 prio):
        if prio == 0 and self._do_drop:
            self.scraper.cnt['tx_msg_drop'] += 1
        else:
            self.scraper.cnt['tx_msg'] += 1
            self.transport.sendto(msg, addr)

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
        double ctl_ping_rate
        double ctl_timeout

        # internal control variables
        float _start_time
        object _disp_cnt
        object _ctl_cnt
        u64 _info_iter
        double _rtt_buf[RTT_BUF_LEN]
        u64 _rtt_buf_ix
        LRUCache _db_ih_age_cache
        list _db_row_pool

    def __cinit__(self):
        # == DHT ==
        # plain list of known infohashes
        self.naked_ihashes = deque([], maxlen=MAX_IHASHES)  # type: ignore

        # info hashes actively being identified
        # indexed by associated nids; this is onto
        self.info_in_flight = {}

        # counter for various statistics of interest, reset every report cycle
        self.cnt = Counter()
        # counter for various statistics of interest, accumulated every rcyc
        self.cnt = Counter()

        self.listener = DHTListener(self)

        self.loop = new_uv_loop()

        self._db_conn = sql.connect(DB_FN.decode('ascii'))
        self._db = self._db_conn.cursor()
        atxreg(self._db_conn.close)
        atxreg(self._db_conn.commit)

        # internal flag variables
        self._disp_cnt = self.cnt.copy()
        self._ctl_cnt = self.cnt.copy()
        self._info_iter = 0
        self._rtt_buf[0] = 0.5
        self._rtt_buf[1] = 0.5
        self._db_ih_age_cache = LRUCache(DB_LRU_MAXSIZE)
        self._db_row_pool = []

        # control variables
        self.ctl_ifl_target = BASE_IFL_TARGET
        self.ctl_ihash_discard = BASE_IHASH_DISCARD
        self.ctl_ihash_refresh = BASE_IHASH_REFRESH
        self.ctl_ping_rate = BASE_PING_RATE
        self.ctl_timeout = BASE_GP_TIMEOUT

    cdef bint rt_random_replace_contact(self, u8 *pnode):
        '''
        Possibly randomly replaces a contact in the routing table with `nid`.
    
        An old contact has a chance to be evicted inversely related to
        its quality given by the quality table.
    
        If no contact is evicted, the new_contact is simply ignored.
        '''

        cdef:
            u64 ax, bx, cx, jx
    
        ax = pnode[0]
        bx = pnode[1]
        cx = randint(0, RT_CONTACTS_PER_BIN)
    
        if check_evict(self.rt_qual[ax][bx][cx]):
            memcpy(self.rt[ax][bx][cx], pnode, NODEINFO_LEN)
            # set_nodeinfo_row(self.rt[ax][bx][cx], pnode)
            return 1

        return 0

    cdef bint rt_adj_quality(self, bytes nid, int delta):
        '''
        Adjusts the quality of the routing contact "nid", if it
        can be found. Otherwise, does nothing.
        '''

        cdef:
            u64 ax, bx, ix
            unsigned char new_qual
    
        ax = nid[0]
        bx = nid[1]
    
        for ix in range(RT_CONTACTS_PER_BIN):
            if is_row_equal(self.rt[ax][bx][ix], nid, IH_LEN):
                new_qual = self.rt_qual[ax][bx][ix] + delta
                if new_qual < MIN_QUAL:
                    new_qual = MIN_QUAL
                elif new_qual > MAX_QUAL:
                    new_qual = MAX_QUAL
                self.rt_qual[ax][bx][ix] = new_qual
                return 1
    
        # failed to find a match
        return 0

    cdef bytes rt_get_neighbor_nid(self, bytes target):
        '''
        Returns a nid from the array of nids `narr` whose first two bytes
        match the target.
        '''

        cdef:
            u64 start_ix
            unsigned char ax, bx, ix
    
        start_ix = randint(0, RT_CONTACTS_PER_BIN)
        ax = target[0]
        bx = target[1]
    
        for ix in range(start_ix, RT_CONTACTS_PER_BIN):
            if not is_row_empty(self.rt[ax][bx][ix]):
                return bytes(self.rt[ax][bx][ix][0:NODEINFO_LEN])
    
        for ix in range(0, start_ix):
            if not is_row_empty(self.rt[ax][bx][ix]):
                return bytes(self.rt[ax][bx][ix][0:NODEINFO_LEN])

    cdef bytes rt_get_random_node(self):
        '''
        Returns a random non-zero node from the current routing table.

        Is much slower when the table is empty. Returns None if it can
        find no node at all.
        '''
    
        cdef:
            u64 start_ix = randint(0, 256 * 256 * RT_CONTACTS_PER_BIN)
            u64 ix, ax, bx, cx
    
        for ix in range(start_ix, 256 * 256 * RT_CONTACTS_PER_BIN):
            ax = ix // (RT_CONTACTS_PER_BIN * 256)
            bx = (ix // RT_CONTACTS_PER_BIN) % 256
            cx = ix % RT_CONTACTS_PER_BIN
            if not is_row_empty(self.rt[ax][bx][cx]):
                return bytes(self.rt[ax][bx][cx][0:NODEINFO_LEN])
    
        for ix in range(0, start_ix):
            cx = ix % RT_CONTACTS_PER_BIN
            bx = (ix // RT_CONTACTS_PER_BIN) % 256
            ax = ix // (RT_CONTACTS_PER_BIN * 256)
            if not is_row_empty(self.rt[ax][bx][cx]):
                return bytes(self.rt[ax][bx][cx][0:NODEINFO_LEN])
    
        return None

    cdef float db_ihash_age(self, bytes ih):
        cdef:
            object res

        out = self._db_ih_age_cache.get(ih)
        if out is None:
            res = self._db.execute(
                '''
                    SELECT last_seen FROM ih_info
                    WHERE ih=?
                    ORDER BY last_seen DESC
                    LIMIT 1
                ''',
                (ih,)
            ).fetchone()

            out = 1e9 if not res else (time() - res[0])
            self._db_ih_age_cache.insert(ih, out)

        return out

    cdef void db_update_peers(self, bytes ih, list peers):
        '''
        Insets the peer information for the given ih into the database.

        Expects clean input.
        '''
        cdef:
            float t = time()
            bytes addr
            u16 port

        self.cnt['info_db_ih_updates'] += 1
        for addr, port in peers:
            self._db_row_pool.append((ih, addr, port, t))

        if len(self._db_row_pool) > ROW_POOL_MAXLEN:
            self._db.executemany(
                '''
                    INSERT OR REPLACE
                    INTO ih_info (ih, peer_addr, peer_port, last_seen)
                    VALUES(?, ?, ?, ?)
                ''',
               self._db_row_pool,
            )
            self._db_row_pool.clear()

    cdef u64 handle_new_nodes(self, object pnodes):
        '''
        Processes a potential array of packed nodes.

        Validates it, and includes all valid-seeming nodes in the routing
        table according to the eviction rules.

        Returns the number of valid nodes processed.
        '''

        if not isinstance(pnodes, bytes):
            self.cnt['bm_bad_nodes'] += 1
            return 0

        n_nodes = len(pnodes) // 26

        cdef int offset

        for ix in range(0, 26 * n_nodes, 26):
            # packed_node = packed_nodes[ix: ix + 26]
            replaced = self.rt_random_replace_contact(pnodes[ix: ix + 26])
            self.cnt['rt_replace_success'] += replaced
            self.cnt['rt_replace_fail'] += (1 - replaced)
            if random() < self.ctl_ping_rate:
                nid, addr = uncompact_nodeinfo(pnodes[ix: ix + 26])
                self.send_pg(nid, addr)

        return n_nodes

    cdef void handle_new_peers(self, bytes nid, object vals):

        cdef:
            bytes ih
            list clean_peers = []

        try:
            ih_or_none = self.info_in_flight[nid]
            if ih_or_none is not None:
                ih = ih_or_none[0]
            else:
                self.cnt['err_peers_nid_invalidated'] += 1
                return
        except KeyError:
            self.cnt['bm_nid_not_in_ifl'] += 1
            return

        if not isinstance(vals, list):
            self.cnt['bm_gp_r_bad_values'] += 1

        elif len(vals) == 0:
            self.cnt['bm_gp_r_empty_vals'] += 1

        else:
            for raw_peer in vals:
                # IMPORTANT
                if len(raw_peer) != PEERINFO_LEN:
                    self.cnt['bm_gp_r_bad_peer'] += 1
                    continue
                ip, port = uncompact_peer_partial(raw_peer)
                if not validate_ip(ip) or port == 0:
                    self.cnt['bm_gp_r_bad_peer'] += 1
                    continue
                clean_peers.append((ip, port))

        if len(clean_peers) == 0:
            self.cnt['bm_gp_r_peers_dirty'] += 1
            # if any of the bad cases above happen, we want this node gone!
            self.rt_adj_quality(nid, -3)
            return

        self.db_update_peers(ih, clean_peers)

    cdef void handle_query(self, tuple saddr, dict msg):

        try:
            tok = msg[b't']
            method = msg[b'q']
            args = msg[b'a']
            nid = args[b'id']
        except KeyError:
            self.cnt['bm_q_bad_query'] += 1
            return

        if len(nid) != 20:
            self.cnt['bm_bad_nid'] += 1
            return

        if method == b'find_node':
            self.cnt['rx_fn'] += 1
            try:
                target = args[b'target']
            except KeyError:
                self.cnt['bm_fn_no_target'] += 1
                return

            # XXX
            pnode = self.rt_get_neighbor_nid(target)
            if pnode is not None:
                self.send_fn_r(pnode, nid, tok, saddr)

        elif method == b'ping':
            self.cnt['rx_pg'] += 1
            self.send_pg_r(nid, tok, saddr)

        elif method == b'get_peers':
            self.cnt['rx_gp'] += 1
            try:
                ih = args[b'info_hash']
            except KeyError:
                self.cnt['bm_gp_no_ih'] += 1
                return

            if len(ih) != 20:
                self.cnt['bm_gp_bad_ih'] += 1
                return

            if self.db_ihash_age(ih) > BASE_IHASH_REFRESH_AGE:
                self.cnt['info_gp_hash_add'] += 1
                self.naked_ihashes.appendleft(ih)
            else:
                self.cnt['info_gp_hash_drop'] += 1

            # effectively samples a random node in the double-bytant
            # this is close to compliant behaviour
            pnode = self.rt_get_neighbor_nid(ih)
            if pnode is not None:
                self.send_gp_r(pnode, nid, tok, saddr)

        elif method == b'announce_peer':
            self.cnt['rx_ap'] += 1
            try:
                if args[b'token'] != TOKEN:
                    # ignore bad token peers
                    self.cnt['bm_ap_bad_token'] += 1
            except KeyError:
                self.cnt['bm_ap_no_token'] += 1
                return

            if b'implied_port' in args and args[b'implied_port'] == 1:
                p_port = saddr[1]
            elif b'port' in args:
                p_port = args[b'port']
            else:
                self.cnt['bm_ap_inconsistent_port']
                return

            try:
                ih = args[b'info_hash']
                if len(ih) != 20:
                    self.cnt['bm_ap_bad_ih'] += 1
                    return
            except KeyError:
                self.cnt['bm_ap_no_ih'] += 1
                return

            self.db_update_peers(ih, [(compact_ip(saddr[0]), p_port)])
            # ap reply is the same as ping
            self.send_pg_r(nid, tok, saddr)

        else:
            try:
                send_s = method.decode('ascii')
            except UnicodeDecodeError:
                send_s = str(method)
            self.cnt[f'bm_method_{send_s}'] += 1

    cdef void handle_response(self, tuple saddr, dict msg):
        '''
        Handles a fully bdecoded response dict.

        Slower than the heuristic method, but exact.
        '''

        cdef:
            int num_good_nodes

        try:
            resp = msg[b'r']
            nid = resp[b'id']
        except KeyError:
            self.cnt['bm_bad_response'] += 1
            return

        if len(nid) != 20:
            self.cnt['bm_bad_nid'] += 1
            return

        if b'token' in resp:
            self.cnt['rx_gp_r'] += 1
            # this only gives us closer nodes:
            if b'values' in resp:
                self.cnt['rx_gp_r_val'] += 1
                self.handle_new_peers(nid, resp[b'values'])

            # some responses have both values and nodes... who cares, we
            # only want the values
            elif b'nodes' in resp:
                # ... first, use throw all the new nodes into the grinder
                self.cnt['rx_gp_r_nod'] += 1
                num_good_nodes = self.handle_new_nodes(resp[b'nodes'])
                # ... then, if the query is still active, ask one of
                # the closer nodes
                ih_or_none = self.info_in_flight.get(nid)
                if ih_or_none is not None:

                    self._rtt_buf[self._rtt_buf_ix] =\
                        monotonic() - ih_or_none[1]
                    self._rtt_buf_ix = (self._rtt_buf_ix + 1) % RTT_BUF_LEN

                    del self.info_in_flight[nid]
                    ih = ih_or_none[0]

                    if num_good_nodes > 0:
                        # peel off the first node, which we check we have
                        new_nid, daddr = uncompact_nodeinfo(resp[b'nodes'])
                        self.send_gp(ih, new_nid, daddr)
                        self.info_in_flight[new_nid] = (ih, monotonic())
                        self.cnt['info_got_next_hop'] += 1
                        self.rt_adj_quality(nid, 1)
                    else:
                        self.cnt['bm_gp_r_no_good_nodes'] += 1
                        self.rt_adj_quality(nid, -2)
                else:
                    self.cnt['bm_gp_r_not_in_ifl']
            else:
                # nids that give garbage are downvoted
                self.rt_adj_quality(nid, -1)
                self.cnt['bm_gp_r_token_only'] += 1

        elif b'nodes' in resp:
            self.cnt['rx_fn_r'] += 1
            self.handle_new_nodes(resp[b'nodes'])

        else:
            self.cnt['rx_other_r'] += 1

    cdef void handle_msg(self, bytes d, tuple saddr):

        try:
            saddr = (saddr[0].encode('ascii'), saddr[1])
        except UnicodeEncodeError:
            self.cnt['bm_bad_saddr']
            return

        try:
            msg = bdecode(d)
        except Exception:
            self.cnt['bm_bdecode_error'] += 1
            return

        cdef parsed_msg out

        err = krpc_bdecode(d, &out)
        self.cnt[f'st_code_{bdx_names[err]}'] += 1

        # if err == bdx_error.NO_ERROR or err == bdx_error.UNKNOWN_Q:
        #     pass
        #     # print(f'>>> BDECODE_ST SUCCESS:')
        #     # print_parsed_msg(&out)
        #     # print('')
        # else:
        #     print(f'!!! BDECODE_ST FAILED WITH {err}\n')
        #     print(f'ON MESSAGE {d}')
        #     print('TRACE\n' + '\n\t'.join(g_trace))
        # # st trial run

        try:
            msg_type = msg[b'y']
        except TypeError:
            self.cnt['bm_msg_not_a_dict'] += 1
            return
        except KeyError:
            self.cnt['bm_no_type'] += 1
            return

        # handle a query
        if msg_type == b'q':
            self.handle_query(saddr, msg)

        elif msg_type == b'r':
            self.handle_response(saddr, msg)

        elif msg_type == b'e':
            self.cnt['rx_e_type'] += 1

        else:
            self.cnt['bm_unknown_type']

    # FIXME implement
    cdef void send_sample_infohashes(self, bytes nid, tuple addr):
        pass

    cdef void send_fn_random(self, u8 *nid, tuple addr):
        self.send_fn(rbytes(IH_LEN), nid, addr)

    cdef void send_fn(self, u8 *target, u8 *nid, tuple addr):
        '''
        Solicit a new random node based on our current self id and the current
        state
        '''
        self.cnt['tx_fn'] += 1
        self.listener.send_msg(
            (
                b'd1:ad2:id20:' + mk_sid(nid) +
                b'6:target20:' + bytes(target[0:20]) +
                b'e1:q9:find_node1:t1:\x771:y1:qe'
            ),
            addr, 0,
        )

    cdef void send_fn_r(self, u8 *pnode, u8 *nid, bytes tok, tuple addr):
        self.cnt['tx_fn_r'] += 1
        self.listener.send_msg(
            (
                b'd1:rd2:id20:' + mk_sid(nid) +
                b'5:nodes26:' + bytes(pnode[0:NODEINFO_LEN]) +
                b'e1:t' + bencode_tok(tok) + b'1:y1:re'
            ),
            addr,
            0
        )
        pass

    cdef send_pg(self, u8 *nid, tuple addr):
        self.cnt['tx_pg'] += 1
        self.listener.send_msg(
            b'd1:ad2:id20:' + mk_sid(nid) + b'e1:q4:ping1:t1:\x771:y1:qe',
            addr,
            0,
        )

    cdef void send_pg_r(self, u8 *nid, bytes tok, tuple daddr):
        '''
        Send a ping reply.
        '''
        self.cnt['tx_pg_r'] += 1
        self.listener.send_msg(
            (
                b'd1:rd2:id20:' + mk_sid(nid) + b'e1:t' +
                bencode_tok(tok) + b'1:y1:re'
            ),
            daddr,
            1,
        )

    cdef void send_gp(self, u8 *ih, u8 *nid, tuple addr, u64 prio=0):
        '''
        Send get_peers query.
        '''
        self.cnt['tx_gp'] += 1
        cdef bytes msg = (
            b'd1:ad2:id20:' + mk_sid(nid) +
            b'9:info_hash20:' + bytes(ih[0:IH_LEN]) +
            b'5:token1:\x88e1:q9:get_peers1:t1:\x771:y1:qe'
        )
        self.listener.send_msg(msg, addr, prio)

    cdef void send_gp_r(self, u8 *pnode, u8 *nid, bytes tok, tuple addr):
        '''
        Send get_peers response.

        Includes one packed node of length 26.
        '''

        self.cnt['tx_gp_r'] += 1
        self.listener.send_msg(
            (
                b'd1:rd2:id20:' + mk_sid(nid) +
                b'5:token1:\x885:nodes26:' + bytes(pnode[0:NODEINFO_LEN]) +
                b'e1:t' + bencode_tok(tok) + b'1:y1:re'
            ),
            addr, 1
        )

    @aio_loop_method(GP_SLEEP)
    def loop_get_peers(self):

        while len(self.info_in_flight) < self.ctl_ifl_target:
            try:
                ih = self.naked_ihashes.pop()
            except IndexError:
                self.cnt['info_raw_ihs_exhausted'] += 1
                rnode = self.rt_get_random_node()
                if rnode:
                    nid, addr = uncompact_nodeinfo(rnode)
                    self.send_fn_random(nid, addr)
                break

            # try to get a node close to the infohash
            packed_node = self.rt_get_neighbor_nid(ih)

            # if we have no node for this section, ask the router
            # XXX this is bad form, we should ask a random other
            # node instead
            if packed_node is None:
                rnode = self.rt_get_random_node()
                if rnode:
                    nid, addr = uncompact_nodeinfo(rnode)
                    self.send_fn(ih, nid, addr)
                continue

            nid, daddr = uncompact_nodeinfo(packed_node)

            if nid in self.info_in_flight:
                self.cnt['info_node_already_in_ifl']
                continue

            self.send_gp(ih, nid, daddr, prio=False)
            self.info_in_flight[nid] = (ih, monotonic())
            self.cnt['info_naked_ih_put_in_ifl'] += 1

    @aio_loop_method(FP_SLEEP)
    def loop_find_nodes(self):
        '''
        Send out find_node randomly.

        The goal is to inject ourselves into as many nodes' routing tables
        as possible, and to refresh the routing table.
        '''
        try:
            ax, bx, cx =\
                randint(0, 256), randint(0, 256), randint(0, RTT_BUF_LEN)
            nid, addr = uncompact_nodeinfo(
                bytes(self.rt[ax][bx][cx][:NODEINFO_LEN]),
            )
            # zero port means zero entry
            if addr[1] > 0:
                self.send_fn_random(nid, addr)

        except KeyError:
            self.cnt['loop_fn_nodes_exchausted'] += 1

    @aio_loop_method(PURGE_SLEEP, init_sleep=5.0)
    def loop_purge_ifl(self):
        '''
        Purges the info_in_flight tables of requests that have timed out
        or been moved on to the next hop.
        '''

        timeout_thresh = monotonic() - self.ctl_timeout

        bad_nids = {
            k for k, v in self.info_in_flight.items()
            if v is None or v[1] < timeout_thresh
        }

        for bad_nid in bad_nids:
            try:
                maybe_ih = self.info_in_flight[bad_nid]
                if maybe_ih is not None:
                    ih = maybe_ih[0]
                    if random() > self.ctl_ihash_discard:
                        self.naked_ihashes.appendleft(ih)

                self.rt_adj_quality(bad_nid, -1)

                del self.info_in_flight[bad_nid]
                self.cnt['info_stale_ifl_purged'] += 1

            except KeyError:
                self.cnt['err_to_purge_disappeared'] += 1


    @aio_loop_method(BOOTSTRAP_SLEEP, init_sleep=BOOTSTRAP_SLEEP)
    def loop_boostrap(self):
        if self.apx_filled_rt_ratio() < 0.01:
            for addr in BOOTSTRAP:
                self.send_fn_random(rbytes(IH_LEN), addr)

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

        dcnt = self.cnt - self._ctl_cnt
        self._ctl_cnt = self.cnt.copy()

        gprr = dcnt['rx_gp_r'] / (dcnt['tx_gp'] + 1)

        if gprr < GPRR_FLOOR:
            self.ctl_ifl_target = max(self.ctl_ifl_target - 1, MIN_IFL_TARGET)
        elif gprr > GPRR_CEIL:
            self.ctl_ifl_target = self.ctl_ifl_target + 1

        if dcnt['tx_msg_drop'] > 10:
            self.ctl_ifl_target = max(self.ctl_ifl_target - 2, MIN_IFL_TARGET)

        self.ctl_ihash_discard = len(self.naked_ihashes) / MAX_IHASHES
        self.ctl_ping_rate = (1 - self.ctl_ihash_discard) / 10

        rtt_stat = self.gp_rtt()
        self.ctl_timeout = rtt_stat.mean + 3 * rtt_stat.std

    @aio_loop_method(INFO_SLEEP, init_sleep=INFO_SLEEP)
    def loop_info(self):
        x = self.cnt - self._disp_cnt
        self._disp_cnt = self.cnt.copy()

        # get peers response rate
        gprr = x["rx_gp_r"] / (x["tx_gp"] + 1)
        # values to nodes ratio (in gp_response)
        vnr = (x["rx_gp_r_val"] + 1) / (x["rx_gp_r_nod"] + 1)
        # db accept rate (number of new infohashes not in db already)
        add, drop = x["info_gp_hash_add"] + 1, x["info_gp_hash_drop"] + 1
        newr = add / (add + drop)

        # get peers round trip time
        rtt = self.gp_rtt()
        # db lru cache efficiency
        lru = self._db_ih_age_cache.stats()[2]
        # routing table replacement rate
        rts, rtf = x["rt_replace_success"] + 1, x["rt_replace_fail"] + 1
        rt_rr  = rts / (rts + rtf)

        info = (
            f'{format_uptime(int(monotonic() - self._start_time)):>9s} | '  # len 11
            f'{x["rx_pg"]:>5d} '  # len 6
            f'{x["rx_fn"]:>5d} {x["rx_fn_r"]:>5d} '  # len 12
            f'{x["rx_gp"]:>5d} '  # len 12
            f'{x["rx_gp_r_val"]:>5d} {x["rx_gp_r_nod"]:>5d} '
            f'{x["rx_ap"]:>5d} | '  # len 11
            f'{x["tx_fn"]:>5d} {x["tx_fn_r"]:>5d} {x["tx_gp"]:>5d} '  # len 14
            f'{x["tx_gp_r"]:>5d} {x["tx_pg"]:>5d} '  # len 12
            f'{x["tx_pg_r"]:>5d} | '  # len 6
            f'{x["info_db_ih_updates"]:>4d} {newr:4.2f} {lru:4.2f} | '  # len 17
            f'{min(gprr, 1.0):>4.2f} {self.ctl_ifl_target:>4d} {vnr:4.2f} '  # len 15
            f'{int(1000 * rtt.mean):>3d}±{int(1000 * rtt.std):>3d} | '  # len 10
            f'{self.average_quality():>4.2f} {rt_rr:4.2f} | '  # len 11
        )

        header_high = (
            '--STATS---| '
            '------------------ RX ------------------- | '
            '---------------- TX --------------- | '
            '----- DB ----- | '
            '-------- PERF -------- | '
            '--- RT -- |'
        )

        header_low = (
            '  uptime  | '
            ' ping '
            '   fn  fn_r '
            '   gp '
            'gp_rv gp_rn '
            '   ap | '
            '   fn  fn_r    gp '
            ' gp_r    pg  pg_r | '
            '  db newr  lru | '
            'gprr load  vnr '
            'rtt(ms) | '
            'qual rtrr |'
        )

        if not self._info_iter:
            LOG.info(header_high)
            LOG.info(header_low)

        LOG.info(info)
        self._info_iter = (self._info_iter + 1) % INFO_HEADER_EVERY

    def run(self):
        # XXX fixme cython time jitters all over the place on startup,
        # this can be later than the first time call in info(), causing
        # stupidity
        self._start_time = monotonic()
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
                self.loop_save_data(),
                self.loop_purge_ifl(),
                self.loop_get_peers(),
                self.loop_find_nodes(),
            ]
        ]
        def stop_all():
            for task in tasks:
                task.cancel()
            self.loop.stop()
            self.loop.close()

        sig.signal(sig.SIGTSTP, self.dump_info)
        # self.loop.add_signal_handler(sig.SIGINT, stop_all)

        self.loop.run_forever()

    def dump_info(self, signal, frame):
        '''
        Prints tables of detailed information on request.
        '''

        self._info_iter = 0

        cdef int table_width = 25 + 12 + 3

        unique_prefixes = {s.split('_')[0] for s in self.cnt if '_' in s}
        tables = {prefix: [] for prefix in unique_prefixes}

        for k, v in self.cnt.items():
            if not '_' in k:
                continue
            prefix = k.split('_')[0]
            tables[prefix].append(f' {k:.<25s}{v:.>12d} ')

        for t in tables.values():
            t.sort()

        while 1 + len(tables) * table_width > TERMINAL_WIDTH and\
                len(tables) > 1:

            by_size = sorted(tables.items(), key=lambda x: len(x[1]))
            # get the smallest
            smk, smt = by_size[0]
            # and second smallest tables
            ssk, sst = by_size[1]

            # append a divider and the contents of the smallest table
            # to the second smallest
            sst.append(' ' + '-' * (25 + 12) + ' ')
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
                fillvalue=' ' * 39,
            )
        ])

        LOG.info(output_string)

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

    cdef double apx_filled_rt_ratio(self):
        cdef:
            u64 ix, jx, kx
            double acc = 0.

        for ix in range(256):
            for jx in range(256):
                for kx in range(RT_CONTACTS_PER_BIN):
                    acc += self.rt[ix][jx][kx][0] / 128.

        return acc / (256 * 256 * RT_CONTACTS_PER_BIN)

    cdef double average_quality(self):
        cdef:
            u64 ix, jx, kx
            double acc = 0.

        for ix in range(256):
            for jx in range(256):
                for kx in range(RT_CONTACTS_PER_BIN):
                    acc += self.rt_qual[ix][jx][kx]

        return acc / (256 * 256 * RT_CONTACTS_PER_BIN)

    cdef mstd gp_rtt(self):
        cdef:
            u64 ix
            double sacc = 0.
            double var = 0.
            mstd result

        result.mean = 0
        result.std = 0

        for ix in range(RTT_BUF_LEN):
            result.mean += self._rtt_buf[ix] / RTT_BUF_LEN

        for ix in range(RTT_BUF_LEN):
            d = self._rtt_buf[ix] - result.mean
            var += d * d

        result.std = sqrt(var / (RTT_BUF_LEN - 1))

        return result

# FIXME prio 2 better sid format
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

cdef tuple uncompact_peer_partial(bytes cp):
    '''
    Unpacks a 6-byte peer info bytes into a 4 byte compact addr and int port.
    '''
    return cp[:4], cp[4] * 256 + cp[5]

cdef tuple uncompact_peer_full(bytes cp):
    '''
    Unpacks a 6-byte peer info bytes into a four-byte address and int port.
    '''
    return inet_ntoa(cp[:4]).encode('ascii'), cp[4] * 256 + cp[5]

cdef tuple uncompact_nodeinfo(bytes pnode):
    '''
    Unpacks a 26-byte note information bytes into a 20-byte node id,
    dot notation ip address and int port.
    '''
    return pnode[0:IH_LEN], uncompact_peer_full(pnode[IH_LEN:NODEINFO_LEN])

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

cdef inline u64 is_row_empty(u8 *row):
    '''
    MEM-UNSAFE
    '''
    return 0 == memcmp(row, ZERO_ROW, NODEINFO_LEN)

cdef inline u64 is_row_equal(u8 *row, u8 *target, u64 up_to):
    '''
    MEM-UNSAFE
    '''
    return 0 == memcmp(row, target, up_to)

cdef inline void set_nodeinfo_row(u8 *row, u8 *target):
    '''
    MEM-UNSAFE
    '''

    memcpy(row, target, NODEINFO_LEN)

    # cdef int ix

    # for ix in range(NODEINFO_LEN):
    #     row[ix] = target[ix]

# FIXME prio 7 randint is slow, use rand
cdef u64 check_evict(u64 qual):
    '''
    Evicts qual x with prob 1 / (2 ^ x).
    '''

    return randint(1 << qual) == 0

# FIXME prio 4 should not need this, should extract raw token from request and
# pass it down
cdef bytes bencode_tok(bytes tok):

    cdef int lt = len(tok)
    cdef bytes slt = str(lt).encode('ascii')

    return slt + b':' + tok

cdef bint validate_ip(u8 *ip):
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

cdef inline void memcpy_bytes(u8 *target, u8 *source, u64 up_to):
    memcpy(target, source, up_to)
