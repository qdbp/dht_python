'''
Stateless DHT scraper.
'''
from atexit import register as atxreg
import asyncio as aio
from asyncio import sleep as asleep
from collections import Counter, deque
from functools import lru_cache, wraps
from ipaddress import IPv4Address
import signal as sig
import sys
import sqlite3 as sql
import traceback as trc
from time import time
from typing import Dict, Any, Optional, List, Tuple, Set, Iterable  # noqa

import numpy as np
from numpy.random import bytes as rbytes, random, randint
from uvloop import new_event_loop as new_uv_loop

# internal
from .bencode import bdecode, BdecodeError
from .util import uncompact_nodeinfo, compact_ip, uncompact_peer_partial
from .util import format_uptime, bencode_tok, validate_ip, mk_sid
from .util import new_sid_addr_table, new_rt_qual_table
from .util import get_neighbor_nid, random_replace_contact, adj_quality
from .util import get_random_node

from vnv.util import save_pickle, load_pickle
from vnv.log import get_logger
LOG = get_logger(__file__)

Addr = Tuple[str, int]

# net: sockets
DHT_LPORT = int(sys.argv[1])

TOK = b'\x77'
TOKEN = b'\x88'

# dht: bootstrap, router.bittorrent.com
BOOTSTRAP = [('67.215.246.10', 6881)]

# info: control
CONTROL_SECS = 1
# get peers reponse rate target
GPRR_FLOOR = 0.30
GPRR_CEIL = 0.40
REPORT_SECS = 5

# loop granularities
FP_SLEEP = 0.05
GP_SLEEP = 0.01
PURGE_SLEEP = 0.05
BOOTSTRAP_SLEEP = 1.0
CONTROL_SLEEP = 1.0
INFO_SLEEP = 5.0
SAVE_SLEEP = 60.0

MAX_NODES = 25000
MAX_IHASHES = 25000
GP_QS_PER_IH = 2
FP_THRESH = MAX_NODES // 2
FP_NUMBER = 5
INFO_HEADER_EVERY = 10
# if the nodes queue is full, we send this many get_peers requests per
# find_node
# drop perfectly good ihashes with this rate to prevent zeroing in on a
# "difficult" set
# IHASH_DECAY_RATE = 0.01

MIN_IFL_TARGET = 10
BASE_IFL_TARGET = 1000
BASE_IHASH_DISCARD = 0.25
BASE_IHASH_REFRESH = 0.03
BASE_PING_RATE = 0.05
BASE_IHASH_REFRESH_AGE = 3600 * 24
BASE_GP_TIMEOUT = 1.0

CTL_TX_SLASH_HOLDOFF = 10
CTL_TX_SLASH_FACTOER = 0.9

DB_FN = './data/dht.db'


def in_data(fn):
    return './data/' + fn


def iter_nodes(packed_nodes: bytes):
    for i in range(0, len(packed_nodes), 26):
        yield uncompact_nodeinfo(packed_nodes[i:i + 26])


# FIXME: take out to vnv
def aio_loop_method(sleep_time: float, init_sleep: float=None):
    def decorator(f):
        @wraps(f)
        async def looped(self):

            if init_sleep is not None:
                await asleep(init_sleep)

            mark = time()
            while True:
                mark = mark + sleep_time
                try:
                    f(self)
                except Exception as e:
                    LOG.error(
                        f'Unhandled error in {f.__qualname__}\n' +
                        trc.format_exc()
                    )
                await asleep(max(mark - time(), 1e-4))

        return looped
    return decorator


class DHTListener:
    '''
    Asynchtonous listener for incoming messages.

    Implements a protocol api.
    '''

    def __init__(self, scraper):
        self.scraper = scraper
        self.cnt = self.scraper.cnt
        self.handle_msg = self.scraper.handle_raw_msg

    def _drop_msg(self, msg, addr):
        self.cnt['tx_msg_drop'] += 1

    def connection_made(self, transport):
        LOG.info('Connection made.')
        self.transport = transport
        self.scraper.send_raw_msg = transport.sendto
        self.scraper.send_raw_msg_prio = transport.sendto

    def error_received(self, exc):
        self.cnt['rx_err_' + exc.__class__.__name__] += 1

    def datagram_received(self, data, saddr):
        try:
            self.handle_msg(data, saddr)
            self.cnt['rx_msg'] += 1
        except OSError as e:
            self.cnt['rx_err_OSError'] += 1
        except Exception as e:
            self.cnt['err_rx_' + e.__class__.__name__] += 1
            LOG.error(f'Unhandled error in handle_raw_msg\n{trc.format_exc()}')

    def pause_writing(self):
        self.scraper.send_raw_msg = self._drop_msg

    def resume_writing(self):
        self.scraper.send_raw_msg = self.transport.sendto


# class MDListener:
#     def connection_made(
# 
# 
class DHTScraper:

    saved_attributes = ['naked_ihashes', 'rt', 'rt_qual']

    def __init__(self):
        # == DHT ==
        # plain list of known infohashes
        self.naked_ihashes = deque([], maxlen=MAX_IHASHES)  # type: ignore

        # info hashes actively being identified
        # indexed by associated nids; this is onto
        self.info_in_flight: Dict[bytes, Optional[Tuple[bytes, float]]] = {}

        # a table of compact sid, addrs indexed by the two-byte routing prefix
        self.rt: np.ndarray = new_sid_addr_table()
        self.rt_qual: np.ndarray = new_rt_qual_table()

        self.load_data()

        # counter for various statistics of interest, reset every report cycle
        self.cnt: Dict[str, int] = Counter()
        # counter for various statistics of interest, accumulated every rcyc
        self.cnt: Dict[str, int] = Counter()

        self.listener = DHTListener(self)

        self.loop = new_uv_loop()

        self._db_conn = sql.connect(DB_FN)
        self._db = self._db_conn.cursor()
        atxreg(self._db_conn.close)
        atxreg(self._db_conn.commit)

        self.send_raw_msg = lambda x, y: ValueError('Listener not ready!')
        self.send_raw_msg_prio = lambda x, y: ValueError('Listener not ready!')

        # internal flag variables
        self._start_time = time()
        self._disp_cnt = self.cnt.copy()
        self._cnt0 = self.cnt.copy()
        self._info_iter = 0
        self._rtt_buf = deque([2e-2, 2e-2], maxlen=100)  # type: ignore

        # control variables
        self.ctl_ifl_target = BASE_IFL_TARGET
        self.ctl_ihash_discard = BASE_IHASH_DISCARD
        self.ctl_ihash_refresh = BASE_IHASH_REFRESH
        self.ctl_ping_rate = BASE_PING_RATE
        self.ctl_timeout = BASE_GP_TIMEOUT

    @lru_cache(maxsize=1 << 10)
    def db_ihash_age(self, ih: bytes) -> float:
        res: Tuple[float] = self._db.execute(
            '''
                SELECT last_seen FROM ih_info
                WHERE ih=?
                ORDER BY last_seen DESC
                LIMIT 1
            ''',
            (ih,)
        ).fetchone()

        if not res:
            return 1e9
        else:
            return time() - res[0]

    def db_update_peers(self, ih: bytes, peers: Iterable[Addr]):
        t = int(time())

        q_vals = [
            (ih, addr, port, t)
            for addr, port in peers
            if port > 0 and validate_ip(addr)
        ]

        if q_vals:
            self._db.executemany(
                '''
                    INSERT OR REPLACE
                    INTO ih_info (ih, peer_addr, peer_port, last_seen)
                    VALUES(?, ?, ?, ?)
                ''',
                q_vals,
            )
            self.cnt['info_db_ih_updates'] += 1
        else:
            self.cnt['bm_all_vals_dirty'] += 1

    def handle_new_nodes(self, packed_nodes: bytes) -> None:
        lpn = len(packed_nodes)
        lpn -= (lpn % 26)
        for ix in range(0, lpn, 26):
            packed_node = packed_nodes[ix: ix + 26]
            replaced = random_replace_contact(
                self.rt, self.rt_qual, packed_node,
            )
            self.cnt['rt_replace_success'] += replaced
            self.cnt['rt_replace_fail'] += (1 - replaced)
            if random() < self.ctl_ping_rate:
                self.send_pg(*uncompact_nodeinfo(packed_node))

    def handle_new_peers(self, nid: bytes, vals: List[bytes]) -> None:

        if not vals:
            self.cnt['bm_gp_r_empty_vals']
            # nodes that give us empty values are noncompliant, PUNISHMENT!!!
            adj_quality(self.rt, self.rt_qual, nid, -3)
            return

        try:
            ih_or_none = self.info_in_flight[nid]
            if ih_or_none is not None:
                ih = ih_or_none[0]
            else:
                self.cnt['err_peers_nid_invalidated'] += 1
                return
        except KeyError:
            self.cnt['bm_peers_nid_not_in_ifl'] += 1
            return

        try:
            self.db_update_peers(ih, map(uncompact_peer_partial, vals))
        except TypeError:
            self.cnt['bm_peers_bad_values'] += 1

    def handle_query(self, saddr, msg: Dict[bytes, Any]) -> None:

        try:
            tok = msg[b't']
            method = msg[b'q']
            args = msg[b'a']
            nid = args[b'id']
        except KeyError:
            self.cnt['bm_q_bad_query'] += 1
            return

        if method == b'find_node':
            self.cnt['rx_fn'] += 1
            try:
                target = args[b'target']
            except KeyError:
                self.cnt['bm_fn_no_target'] += 1
                return

            pnode = bytes(self.rt[target[0]][target[1]])
            self.send_fn_r(tok, pnode, nid, saddr)

        elif method == b'ping':
            self.cnt['rx_pg'] += 1
            self.send_pg_r(tok, nid, saddr)

        elif method == b'get_peers':
            self.cnt['rx_gp'] += 1
            try:
                ih = args[b'info_hash']
            except KeyError:
                self.cnt['bm_gp_no_ih'] += 1
                return

            if self.db_ihash_age(ih) > BASE_IHASH_REFRESH_AGE:
                self.cnt['info_gp_hash_add'] += 1
                self.naked_ihashes.appendleft(ih)
            else:
                self.cnt['info_gp_hash_drop'] += 1

            # effectively samples a random node in the double-bytant
            # this is close to compliant behaviour
            pnode = bytes(self.rt[ih[0]][ih[1]])
            self.send_gp_r(tok, pnode, nid, saddr)

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
            except KeyError:
                self.cnt['bm_ap_no_ih'] += 1
                return

            self.db_update_peers(ih, [(compact_ip(saddr[0]), p_port)])
            # ap reply is the same as ping
            self.send_pg_r(tok, nid, saddr)

        else:
            try:
                send_s = method.decode('ascii')
            except UnicodeDecodeError:
                send_s = str(method)
            self.cnt[f'bm_q_unknown_method_{send_s}'] += 1

    def handle_response(self, saddr, msg: Dict[bytes, Any]) -> None:
        '''
        Handles a fully bdecoded response dict.

        Slower than the heuristic method, but exact.
        '''

        try:
            resp = msg[b'r']
            nid = resp[b'id']
        except KeyError:
            self.cnt['bm_bad_response'] += 1
            return

        if b'token' in resp:
            self.cnt['rx_gp_r'] += 1
            # this only gives us closer nodes:
            if b'values' in resp:
                self.cnt['rx_gp_r_val'] += 1
                self.handle_new_peers(nid, resp[b'values'])
                # nids that deliver get a quality bump
                adj_quality(self.rt, self.rt_qual, nid, 2)

            elif b'nodes' in resp:
                # ... first, use throw all the new nodes into the grinder
                self.cnt['rx_gp_r_nod'] += 1
                self.handle_new_nodes(resp[b'nodes'])
                # ... then, if the query is still active, ask one of
                # the closer nodes
                ih_or_none = self.info_in_flight.get(nid)
                if ih_or_none is not None:

                    self._rtt_buf.appendleft(time() - ih_or_none[1])

                    del self.info_in_flight[nid]
                    ih = ih_or_none[0]

                    new_nid, daddr = uncompact_nodeinfo(resp[b'nodes'])
                    if not new_nid:
                        self.cnt['bm_gp_r_empty_nodes'] += 1
                        return

                    self.send_gp(ih, new_nid, daddr)
                    self.info_in_flight[new_nid] = (ih, time())
                    self.cnt['info_got_next_hop_node'] += 1

                else:
                    self.cnt['bm_gp_r_not_in_ifl']
            else:
                # nids that give garbage are downvoted
                adj_quality(self.rt, self.rt_qual, nid, -1)
                self.cnt['bm_gp_r_token_only'] += 1

        elif b'nodes' in resp:
            self.cnt['rx_fn_r'] += 1
            self.handle_new_nodes(resp[b'nodes'])

        else:
            self.cnt['rx_other_r'] += 1

    def handle_raw_msg(self, d: bytes, saddr) -> None:

        try:
            saddr = (saddr[0].encode('ascii'), saddr[1])
        except UnicodeEncodeError:
            self.cnt['bm_bad_saddr']
            return

        try:
            msg = bdecode(d)
        except BdecodeError:
            self.cnt['bm_bdecode_error']
            return

        try:
            msg_type = msg[b'y']
        except TypeError:
            self.cnt['bm_msg_not_a_dict'] += 1
            return
        except KeyError:
            self.cnt['b_no_type'] += 1
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
    def send_sample_infohashes(self, nid: bytes, addr):
        pass

    def send_fn_random(self, nid: bytes, addr) -> None:
        return self.send_fn(rbytes(20), nid, addr)

    def send_fn(self, target: bytes, nid: bytes, addr) -> None:
        '''
        Solicit a new random node based on our current self id and the current
        state
        '''
        self.cnt['tx_fn'] += 1
        self.send_raw_msg(
            (
                b'd1:ad2:id20:' + mk_sid(nid) +
                b'6:target20:' + target +
                b'e1:q9:find_node1:t1:\x771:y1:qe'
            ),
            addr,
        )

    def send_fn_r(self, tok, pnode, nid, addr):
        self.cnt['tx_fn_r'] += 1
        self.send_raw_msg(
            (
                b'd1:rd2:id20:' + mk_sid(nid) +
                b'5:nodes26:' + pnode +
                b'e1:t' + bencode_tok(tok) + b'1:y1:re'
            ),
            addr,
        )
        pass

    def send_pg(self, nid: bytes, addr: Addr) -> None:
        self.cnt['tx_pg'] += 1
        self.send_raw_msg(
            b'd1:ad2:id20:' + mk_sid(nid) + b'e1:q4:ping1:t1:\x771:y1:qe',
            addr,
        )

    def send_pg_r(self, tok: bytes, nid: bytes, addr: Addr) -> None:
        '''
        Send a ping reply.
        '''
        self.cnt['tx_pg_r'] += 1
        self.send_raw_msg(
            (
                b'd1:rd2:id20:' + mk_sid(nid) + b'e1:t' +
                bencode_tok(tok) + b'1:y1:re'
            ),
            addr,
        )

    def send_gp(self, ih: bytes, nid: bytes, addr: Addr, prio=False):
        '''
        Send get_peers query.
        '''
        self.cnt['tx_gp'] += 1
        msg = (
            b'd1:ad2:id20:' + mk_sid(nid) + b'9:info_hash20:' +
            ih + b'5:token1:\x88e1:q9:get_peers1:t1:\x771:y1:qe'
        )
        if prio:
            self.send_raw_msg_prio(msg, addr)
        else:
            self.send_raw_msg(msg, addr)

    def send_gp_r(self, tok, pnode, nid, addr) -> None:
        '''
        Send get_peers response.

        Includes one packed node of length 26.
        '''

        self.cnt['tx_gp_r'] += 1
        self.send_raw_msg(
            (
                b'd1:rd2:id20:' + mk_sid(nid) +
                b'5:token1:\x885:nodes26:' + pnode +
                b'e1:t' + bencode_tok(tok) + b'1:y1:re'
            ),
            addr,
        )

    @aio_loop_method(GP_SLEEP)
    def loop_get_peers(self):
        while len(self.info_in_flight) < self.ctl_ifl_target:
            try:
                ih = self.naked_ihashes.pop()
            except IndexError:
                self.cnt['info_naked_hashes_exhausted'] += 1
                rnode = get_random_node(self.rt)
                if rnode:
                    self.send_fn_random(*uncompact_nodeinfo(rnode))
                break

            # try to get a node close to the infohash
            packed_node = get_neighbor_nid(self.rt, ih)

            # if we have no node for this section, ask the router
            # XXX this is bad form, we should ask a random other
            # node instead
            if packed_node is None:
                rnode = get_random_node(self.rt)
                if rnode:
                    _, sid, addr = self.get_nid_sid_addr(rnode)
                    self.send_fn(ih, sid, addr)
                continue

            nid, daddr = uncompact_nodeinfo(packed_node)

            if nid in self.info_in_flight:
                self.cnt['info_node_already_in_ifl']
                continue

            self.send_gp(ih, nid, daddr, prio=False)
            self.info_in_flight[nid] = (ih, time())
            self.cnt['info_naked_ih_put_in_ifl'] += 1

    @aio_loop_method(FP_SLEEP)
    def loop_find_nodes(self):
        '''
        Send out find_node randomly.

        The goal is to inject ourselves into as many nodes' routing tables
        as possible, and to refresh the routing table.
        '''
        try:
            ax, bx, cx = randint(0, 256), randint(0, 256), randint(0, 5)
            nid, addr = uncompact_nodeinfo(bytes(self.rt[ax, bx, cx]))
            # zero port means zero entry
            if addr[1] > 0:
                self.send_fn_random(nid, addr)

        except KeyError:
            self.cnt['loop_fn_nodes_exchausted']

    @aio_loop_method(PURGE_SLEEP, init_sleep=5.0)
    def loop_purge_ifl(self):
        '''
        Purges the info_in_flight tables of requests that have timed out
        or been moved on to the next hop.
        '''

        timeout_thresh = time() - self.ctl_timeout

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

                adj_quality(self.rt, self.rt_qual, bad_nid, -1)

                del self.info_in_flight[bad_nid]
                self.cnt['info_stale_ifl_purged'] += 1

            except KeyError:
                self.cnt['err_to_purge_disappeared'] += 1

    @aio_loop_method(BOOTSTRAP_SLEEP)
    def loop_boostrap(self):
        if self.apx_filled_rt_ratio < 0.01:
            for addr in BOOTSTRAP:
                self.send_fn_random(rbytes(20), addr)

    @aio_loop_method(SAVE_SLEEP, init_sleep=SAVE_SLEEP)
    def loop_save_data(self):
        self.dump_data()
        self._db_conn.commit()
        LOG.info('Saved data.')

    @aio_loop_method(CONTROL_SLEEP, init_sleep=CONTROL_SLEEP)
    def loop_control(self):
        '''
        Tracks and dynamically updates parameters controlling the operation
        of the scraper to optimize performance.
        '''

        dcnt = self.cnt - self._cnt0
        self._cnt0 = self.cnt.copy()

        gprr = dcnt['rx_gp_r'] / (dcnt['tx_gp'] + 1)

        if gprr < GPRR_FLOOR:
            self.ctl_ifl_target = max(self.ctl_ifl_target - 1, MIN_IFL_TARGET)
        elif gprr > GPRR_CEIL:
            self.ctl_ifl_target = self.ctl_ifl_target + 1

        if dcnt['tx_msg_drop'] > 10:
            self.ctl_ifl_target = max(self.ctl_ifl_target - 2, MIN_IFL_TARGET)

        self.ctl_ihash_discard = len(self.naked_ihashes) / MAX_IHASHES
        self.ctl_ping_rate = (1 - self.ctl_ihash_discard) / 10

        rttm, rtts = self.gp_rtt
        self.ctl_timeout = rttm + 3 * rtts

    @aio_loop_method(INFO_SLEEP, init_sleep=INFO_SLEEP)
    def loop_info(self):
        x = self.cnt - self._disp_cnt
        self._disp_cnt = self.cnt.copy()

        # get peers response rate
        gprr = x["rx_gp_r"] / (x["tx_gp"] + 1)
        # values to nodes ratio (in gp_response)
        vnr = (x["rx_gp_r_val"] + 1) / (x["rx_gp_r_nod"] + 1)
        # db accept rate (number of new infohashes not in db already)
        newr = (
            x["info_gp_hash_add"] + 1) / (
            ((x["info_gp_hash_drop"] + 1) + (x["info_gp_hash_add"] + 1))
        )

        info = (
            f'{format_uptime(int(time() - self._start_time)):9s} | '  # len 11
            f'{x["rx_pg"]:>5d} '  # len 6
            f'{x["rx_fn"]:>5d} {x["rx_fn_r"]:>5d} '  # len 12
            f'{x["rx_gp"]:>5d} '  # len 12
            f'{x["rx_gp_r_val"]:>5d} {x["rx_gp_r_nod"]:>5d} '
            f'{x["rx_ap"]:>5d}    | '  # len 11
            f'{x["tx_fn"]:>5d} {x["tx_fn_r"]:>5d} {x["tx_gp"]:>5d} '  # len 14
            f'{x["tx_gp_r"]:>5d} {x["tx_pg"]:>5d} '  # len 12
            f'{x["tx_pg_r"]:>5d} | '  # len 6
            f'{x["info_db_ih_updates"]:>4d} {newr:4.2f} | '  # len 10
            f'{min(gprr, 1.0):>4.2f} {self.ctl_ifl_target:>4d} '  # len 10
            f'{len(self.naked_ihashes)/MAX_IHASHES:>4.2f} '  # len 5
            f'{self.average_quality:>6.4f} {vnr:4.2f} '  # len 12
            f'{self.gp_rtt[0]:>4.2f} {self.gp_rtt[1]:>5.3f} '  # len 11
        )

        header = (
            'uptime  |rx>'
            ' ping '
            '   fn  fn_r '
            '   gp '
            'gp_rv gp_rn '
            '   ap  |tx>'
            '   fn  fn_r    gp '
            ' gp_r    pg  pg_r | '
            '  db newr | '
            'gprr load '
            'nihs '
            '  qual  vnr '
            ' rtt  (sd) '
        )

        if not self._info_iter:
            LOG.info(header)

        LOG.info(info)
        self._info_iter = (self._info_iter + 1) % INFO_HEADER_EVERY

    def run(self):
        sig.signal(sig.SIGTSTP, self.dump_info)

        run_listener = self.loop.create_datagram_endpoint(
            lambda: self.listener, local_addr=('0.0.0.0', DHT_LPORT)
        )

        all_tasks = aio.gather(
            self.loop_boostrap(),
            self.loop_save_data(),
            self.loop_purge_ifl(),
            self.loop_get_peers(),
            self.loop_find_nodes(),
            self.loop_info(),
            self.loop_control(),
            run_listener,
            loop=self.loop,
        )

        self.loop.run_until_complete(all_tasks)

    def dump_info(self, signum, frame):

        self._info_iter = 0
        s = '\n'.join(
            [
                ' ' * 15 + '{:.<45}{:->15}'
                .format(k, v)
                for k, v in sorted(self.cnt.items())
                if '_' in k
            ]
        )
        LOG.info('error counts:\n' + s)

    def dump_data(self):
        for fn in self.saved_attributes:
            save_pickle(getattr(self, fn), in_data(fn))

    def load_data(self):
        for fn in self.saved_attributes:
            try:
                setattr(self, fn, load_pickle(in_data(fn)))
            except (FileNotFoundError, OSError):
                continue

    @property
    def apx_filled_rt_ratio(self):
        return np.mean(self.rt[:, :, :, 0]) / 127.5

    @property
    def average_quality(self):
        return np.mean(self.rt_qual)

    @property
    def gp_rtt(self):
        return np.mean(self._rtt_buf), np.std(self._rtt_buf)
