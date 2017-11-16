'''
Stateless DHT scraper.
'''
from atexit import register as atxreg
import asyncio as aio
from asyncio import sleep as asleep
from collections import Counter, deque, defaultdict
from functools import lru_cache, wraps
from hashlib import sha1
from ipaddress import IPv4Address
import re
import signal as sig
import socket as sck
import sys
import sqlite3 as sql
import traceback as trc
from time import sleep, time
from typing import Callable, Dict, Any, Optional, Tuple, Set, Iterable

from numpy.random import bytes as rbytes, random
from uvloop import new_event_loop as new_uv_loop

# internal
from .bencode import bdecode, BdecodeError
from .bencode import mk_gp_fp_reply, mk_ping_ap_reply
from .util import uncompact_nodeinfo, uncompact_addr, uncompact_port
from .util import format_uptime

from vnv.util import save_pickle, load_pickle
from vnv.log import get_logger
LOG = get_logger(__file__)

Addr = Tuple[str, int]

# net: sockets
DHT_LPORT = int(sys.argv[1])

# this is a reference node we given when replying to find_peer requests
REF_NODE = (
    b'\xb3\x97\xd6\x06\xa3s{\xa5Q\x03@>\x14P'
    b'\xd4L\xc8\xd6\x99>P\x1f\xc3\xe6A\x9b'
)

TOK = b'\x77'
TOKEN = b'\x88'

# dht: bootstrap, router.bittorrent.com
BOOTSTRAP = [('67.215.246.10', 6881)]

# info: control
CONTROL_SECS = 1
# get peers reponse rate target
GPRR_FLOOR = 0.7
GPRR_CEIL = 0.8
REPORT_SECS = 5

# loop granularities
FP_SLEEP = 0.1
GP_SLEEP = 0.01
PURGE_SLEEP = 0.25
BOOTSTRAP_SLEEP = 1.0
CONTROL_SLEEP = 1.0
INFO_SLEEP = 5.0
SAVE_SLEEP = 60.0

MAX_NODES = 100000
GP_TIMEOUT = 1.0
GP_QS_PER_IH = 3
FP_THRESH = MAX_NODES // 2
FP_NUMBER = 5
INFO_HEADER_EVERY = 10
# if the nodes queue is full, we send this many get_peers requests per
# find_node
IHASH_REFRESH_RATE = 0.03
MIN_IFL_TARGET = 100
INIT_IFL_TARGET = 1000

DB_FN = './data/dht.db'


def in_data(fn):
    return './data/' + fn


SALT = b'\x13\x37' + int.to_bytes(DHT_LPORT, 2, 'big')


@lru_cache(maxsize=1 << 20)
def mk_sid(nid: bytes) -> bytes:
    return nid[:2] + sha1(nid + SALT).digest()[2:]  # type: ignore


def iter_nodes(nodes: bytes):
    for i in range(0, len(nodes), 26):
        yield uncompact_nodeinfo(nodes[i:i + 26])


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
        self.scraper.send_msg = transport.sendto
        self.scraper.send_msg_prio = transport.sendto

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
        self.scraper.send_msg = self._drop_msg

    def resume_writing(self):
        self.scraper.send_msg = self.transport.sendto


class DHTScraper:

    saved_attributes = ['naked_ihashes', 'nodes']

    def __init__(self):
        # == DHT ==
        # plain list of known infohashes
        self.naked_ihashes: Set[bytes] = set()

        # info hashes actively being identified
        # indexed by associated nids; this is onto
        self.info_in_flight: Dict[bytes, Optional[Tuple[bytes, float]]] = {}

        # a set of nodes to use as a pool to find more nodes and
        # send get_peers queries
        self.nodes: Set[bytes] = set()

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

        self.send_msg = lambda x, y: ValueError('Listener not ready!')
        self.send_msg_prio = lambda x, y: ValueError('Listener not ready!')

        # control variables
        self.ifl_target = 1000
        self._start_time = time()
        self._disp_cnt = self.cnt.copy()
        self._cnt0 = self.cnt.copy()
        self._info_iter = 0

    # TODO: update docstring
    def handle_new_nodes(self, packed_nodes: bytes) -> None:
        '''
        Handles new nodes received message.

        Since we do not store nodes we know, we must always have some
        find_nodes queries in flight, which will trigger this function.
        Since each find_nodes query returns more than one node back
        on average, we can use the extra calls to send get_peers queries.
        '''
        if len(self.nodes) < MAX_NODES:
            for ix in range(0, len(packed_nodes), 26):
                self.nodes.add(packed_nodes[ix:ix + 26])

    @lru_cache(maxsize=1 << 20)
    def db_have_ihash(self, ih):
        res = self._db.execute('SELECT ih FROM ih_info WHERE ih=?', (ih,))
        return bool(res.fetchone())

    def db_update_peers(self, ih: bytes, peers: Iterable[Addr]):
        t = int(time())
        self._db.executemany(
            '''INSERT OR REPLACE INTO ih_info (
                ih, peer_addr, peer_port, last_seen
            ) VALUES(?, ?, ?, ?);''',
            [
                (ih, addr, port, t)
                for addr, port in peers
                if port > 0 and IPv4Address(addr).is_global
            ]
        )
        self.cnt['info_db_ih_updates'] += 1

    def handle_new_peers(self, nid, resp):
        try:
            ih = self.info_in_flight[nid][0]
        except KeyError:
            self.cnt['bm_peers_nid_not_in_ifl'] += 1
            return

        try:
            self.db_update_peers(
                ih, [uncompact_port(p) for p in resp[b'values']]
            )
            self.cnt['info_got_peers'] += 1
        except TypeError:
            self.cnt['bm_peers_bad_values'] += 1

    def handle_query(self, saddr, msg: Dict[bytes, Any]) -> Optional[bytes]:

        try:
            tok = msg[b't']
            method = msg[b'q']
            args = msg[b'a']
            nid = args[b'id']
        except KeyError:
            self.cnt['bm_bad_query'] += 1
            return None

        sid = mk_sid(nid)

        if method == b'find_node':
            self.cnt['rx_find_node'] += 1
            return None
            self.cnt['tx_find_node_r'] += 1
            return mk_gp_fp_reply(sid, tok, 0)

        elif method == b'ping':
            self.cnt['rx_ping'] += 1
            return None
            self.cnt['tx_ping_r'] += 1
            return mk_ping_ap_reply(sid, tok)

        elif method == b'get_peers':
            ih = args[b'info_hash']
            if not self.db_have_ihash(ih) or random() < IHASH_REFRESH_RATE:
                self.naked_ihashes.add(args[b'info_hash'])

            self.cnt['rx_get_peers'] += 1
            return None
            self.cnt['tx_get_peers_r'] += 1
            return mk_gp_fp_reply(sid, tok, 1)

        elif method == b'announce_peer':
            if args[b'token'] != TOKEN:
                self.cnt['bm_bad_token'] += 1
                # ignore bad token peers
                return None

            if b'implied_port' in args and args[b'implied_port'] == 1:
                p_port = saddr[1]
            else:
                p_port = args[b'port']

            self.db_update_peers(args[b'info_hash'], ((saddr[0], p_port),))

            self.cnt['rx_announce_peer'] += 1
            return None
            self.cnt['tx_announce_peer_r'] += 1
            return mk_ping_ap_reply(sid, tok)

        else:
            try:
                query_s = method.decode('ascii')
            except UnicodeDecodeError:
                query_s = str(method)
            self.cnt[f'rx_query_{query_s}'] += 1
            return None

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
            self.cnt['rx_get_peers_r'] += 1
            # this only gives us closer nodes:
            if b'values' in resp:
                self.handle_new_peers(nid, resp)

            elif b'nodes' in resp:
                # ... first, use throw all the new nodes into the grinder
                self.handle_new_nodes(resp[b'nodes'])
                # ... then, if the query is still active, ask one of
                # the closer nodes
                ih_or_none = self.info_in_flight.get(nid)
                if ih_or_none is not None:

                    del self.info_in_flight[nid]
                    ih = ih_or_none[0]

                    new_nid, daddr = uncompact_nodeinfo(resp[b'nodes'])
                    if not new_nid:
                        self.cnt['bm_empty_next_hop_nodes'] += 1
                        return

                    self.query_get_peers(mk_sid(new_nid), ih, daddr)
                    self.info_in_flight[new_nid] = (ih, time() + GP_TIMEOUT)
                    self.cnt['info_got_next_hop_node'] += 1

                else:
                    self.cnt['bm_gp_reply_not_in_ifl']
            else:
                self.cnt['bm_token_no_peers_or_nodes'] += 1

        elif b'nodes' in resp:
            self.cnt['rx_find_node_r'] += 1
            self.handle_new_nodes(resp[b'nodes'])

        else:
            self.cnt['rx_other_r'] += 1

    def handle_raw_msg(self, d: bytes, addr) -> None:

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
            reply_msg = self.handle_query(addr, msg)
            if reply_msg is not None:
                self.send_msg_prio(reply_msg, addr)

        elif msg_type == b'r':
            self.handle_response(addr, msg)

        elif msg_type == b'e':
            self.cnt['rx_e_type'] += 1
        else:
            self.cnt['bm_unknown_type']

    def query_find_random_node(self, sid, addr):
        '''
        Solicit a new random node based on our current self id and the current
        state
        '''
        self.cnt['tx_find_node'] += 1
        msg = (
            b'd1:ad2:id20:' + sid +
            b'6:target20:' + rbytes(20) +
            b'e1:q9:find_node1:t1:\x771:y1:qe'
        )
        self.send_msg(msg, addr)

    def query_ping_node(self, sid, addr):
        self.cnt['tx_ping'] += 1
        msg = b'd1:ad2:id20:' + sid + b'e1:q4:ping1:t1:\x771:y1:qe'
        self.send_msg(msg, addr)

    def query_get_peers(self, sid, info_hash, addr, prio=False):
        self.cnt['tx_get_peers'] += 1
        msg = (
            b'd1:ad2:id20:' + sid + b'9:info_hash20:' +
            info_hash + b'5:token1:\x88e1:q9:get_peers1:t1:\x771:y1:qe'
        )
        if prio:
            self.send_msg_prio(msg, addr)
        else:
            self.send_msg(msg, addr)

    def get_next_nid_sid_addr(self):
        nid, addr = uncompact_nodeinfo(self.nodes.pop())
        sid = mk_sid(nid)
        return nid, sid, addr

    @aio_loop_method(GP_SLEEP)
    def loop_get_peers(self):
        while len(self.info_in_flight) < self.ifl_target:
            try:
                ih = self.naked_ihashes.pop()
            except KeyError:
                self.cnt['info_naked_hashes_exhausted'] += 1
                return

            for i in range(GP_QS_PER_IH):
                try:
                    nid, sid, addr = self.get_next_nid_sid_addr()
                except KeyError:
                    self.cnt['info_nodes_exhausted']
                    return

                if nid in self.info_in_flight:
                    self.cnt['info_node_already_in_ifl']
                    continue

                self.query_get_peers(sid, ih, addr, prio=False)
                self.info_in_flight[nid] = (ih, time() + GP_TIMEOUT)
                self.cnt['info_naked_ih_put_in_ifl'] += 1

    @aio_loop_method(FP_SLEEP)
    def loop_find_nodes(self):
        '''
        Send out find_node.

        The goal is to inject ourselves into as many node's routing tables
        as possible.
        '''
        try:
            if len(self.nodes) < FP_THRESH:
                for i in range(FP_NUMBER):
                    _, sid, addr = self.get_next_nid_sid_addr()
                    self.query_find_random_node(sid, addr)
        except KeyError:
            self.cnt['loop_fn_nodes_exchausted']

    @aio_loop_method(PURGE_SLEEP, init_sleep=5.0)
    def loop_purge_ifl(self):
        '''
        Purges the info_in_flight tables of requests that have timed out
        or been moved on to the next hop.
        '''

        cur_time = time()

        to_pop = {
            k for k, v in self.info_in_flight.items()
            if v is None or v[1] < cur_time
        }

        for timed_out in to_pop:
            try:
                maybe_ih = self.info_in_flight[timed_out]
                if maybe_ih is not None:
                    ih = maybe_ih[0]
                    if not self.db_have_ihash(ih) or\
                            random() < IHASH_REFRESH_RATE:
                        self.naked_ihashes.add(ih)
                del self.info_in_flight[timed_out]
                self.cnt['info_stale_ifl_purged'] += 1

            except KeyError:
                self.cnt['err_to_purge_disappeared'] += 1

    @aio_loop_method(BOOTSTRAP_SLEEP)
    def loop_boostrap(self):
        if len(self.nodes) < 10:
            for addr in BOOTSTRAP:
                self.query_find_random_node(rbytes(20), addr)
            LOG.info('Bootstrapped.')

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

        gprr = dcnt['rx_get_peers_r'] / (dcnt['tx_get_peers'] + 1)

        if gprr < GPRR_FLOOR:
            self.ifl_target = max(self.ifl_target - 1, MIN_IFL_TARGET)
        elif gprr > GPRR_CEIL:
            self.ifl_target = self.ifl_target + 1

    @aio_loop_method(INFO_SLEEP, init_sleep=INFO_SLEEP)
    def loop_info(self):
        x = self.cnt - self._disp_cnt
        self._disp_cnt = self.cnt.copy()

        # load_factor = ((self.ifl_target - MIN_IFL_TARGET) /
        #     (MAX_IFL_TARGET - MIN_IFL_TARGET))

        # get peers response rate
        gprr = x["rx_get_peers_r"] / (x["tx_get_peers"] + 1)

        info = (
            f'{format_uptime(int(time() - self._start_time)):9s} | '  # len 11
            f'{x["rx_ping"]:>5d} '  # len 6
            f'{x["rx_find_node"]:>5d} {x["rx_find_node_r"]:>5d} '  # len 12
            f'{x["rx_get_peers"]:>5d} {x["rx_get_peers_r"]:>5d} '  # len 12
            f'{x["rx_announce_peer"]:>5d}    | '  # len 11
            f'{x["tx_find_node"]:>5d} {x["tx_get_peers"]:>5d} | '  # len 14
            f'{x["info_db_ih_updates"]:>4d} '  # len 5
            f'{min(gprr, 1.0):>4.2f} {self.ifl_target:>4d}'  # len 5
        )

        header = (
            'uptime  |rx>'
            ' ping '
            '   fn  fn_r '
            '   gp  gp_r '
            '   ap  |tx>'
            '   fn    gp | '
            '  db gprr load'
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

        s = '\n'.join(
            [
                ' ' * 15 + '{:.<30}{:->15}'
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
