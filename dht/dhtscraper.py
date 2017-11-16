'''
Stateless DHT scraper.
'''
from atexit import register as atxreg
import asyncio as aio
from asyncio import sleep as asleep
from collections import Counter, deque, defaultdict
from functools import lru_cache
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

from vnv.util import save_pickle, load_pickle
from vnv.log import get_logger
from vnv.np import autoreg
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

# dht: bootstrap
BOOTSTRAP = [('67.215.246.10', 6881)]

# info: control
CONTROL_SECS = 1
# get peers reponse rate target
GPRR_TARGET = 0.8

REPORT_SECS = 5

MAX_NODES = 100000
GP_TIMEOUT = 1.0
GP_PURGE_TIMER = 0.25
GP_QS_PER_IH = 3
FP_THRESH = MAX_NODES // 2
FP_SLEEP = 0.05
FP_NUMBER = 5
# if the nodes queue is full, we send this many get_peers requests per
# find_node
IHASH_REFRESH_RATE = 0.03
MAX_IFL_TARGET = 2000
MIN_IFL_TARGET = 1000

DB_FN = './data/dht.db'

def in_data(fn):
    return '/home/main/programming/python/dht/data/' + fn


SALT = b'\x13\x37' + int.to_bytes(DHT_LPORT, 2, 'big')


@lru_cache(maxsize=1 << 20)
def mk_sid(nid: bytes) -> bytes:
    return nid[:2] + sha1(nid + SALT).digest()[2:]  # type: ignore


def iter_nodes(nodes: bytes):
    for i in range(0, len(nodes), 26):
        yield uncompact_nodeinfo(nodes[i:i + 26])


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
        except BlockingIOError:
            self.cnt['rx_exhausted_input'] += 1
        except (BdecodeError, ValueError, IndexError):
            self.cnt['bm_bdecode_err'] += 1
        except OSError:
            self.cnt['rx_os_err'] += 1
        except Exception as e:
            LOG.error(f'Unhandled rx erroe\n{trc.format_exc()}')
            self.cnt['err_rx_' + e.__class__.__name__] += 1

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
        self.cum_cnt: Dict[str, int] = Counter()

        self.listener = DHTListener(self)

        self.loop = new_uv_loop()

        self._db_conn = sql.connect(DB_FN)
        self._db = self._db_conn.cursor()
        atxreg(self._db_conn.close)
        atxreg(self._db_conn.commit)

        self.send_msg = lambda x, y: ValueError('Listener not ready!')
        self.send_msg_prio = lambda x, y: ValueError('Listener not ready!')

        # control variables
        self.ifl_target = MAX_IFL_TARGET

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
            # FIXME: persistent storage and md lookup
            self.db_update_peers(
                ih, [uncompact_port(p) for p in resp[b'values']]
            )
            self.cnt['info_got_peers']
        except TypeError:
            self.cnt['bm_peers_bad_values'] += 1
        except KeyError:
            self.cnt['info_peers_nid_not_in_ifl'] += 1

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

        resp = msg[b'r']
        nid = resp[b'id']

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
                    self.info_in_flight[nid] = None
                    ih = ih_or_none[0]

                    # if we already found this infohash, return
                    if self.db_have_ihash(ih):
                        self.cnt['info_ifl_evicted_ih_in_db'] += 1
                        return

                    # else, query one node for the next hop
                    for new_nid, daddr in iter_nodes(resp[b'nodes']):
                        self.info_in_flight[new_nid] =\
                            (ih, time() + GP_TIMEOUT)
                        self.query_get_peers(mk_sid(new_nid), ih, daddr)
                        self.cnt['info_got_next_hop_node'] += 1
                        break
                    else:
                        self.cnt['info_empty_next_hop'] += 1
                else:
                    self.cnt['info_gp_reply_not_in_ifl']
            else:
                self.cnt['bm_token_no_peers_or_nodes'] += 1

        elif b'nodes' in resp:
            self.cnt['rx_find_node_r'] += 1
            self.handle_new_nodes(resp[b'nodes'])

        else:
            self.cnt['rx_other_r'] += 1

    def handle_raw_msg(self, d: bytes, addr) -> None:

        msg = bdecode(d)

        try:
            msg_type = msg.get(b'y')
        except AttributeError:
            self.cnt['bm_message_not_a_dict'] += 1
            return

        # handle a query
        if msg_type == b'q':
            reply_msg = self.handle_query(addr, msg)
            if reply_msg is not None:
                self.send_msg_prio(reply_msg, addr)

        elif msg_type == b'r':
            self.handle_response(addr, msg)
        elif msg_type == b'e':
            self.cnt['bm_e_type'] += 1
        else:
            self.cnt['bm_bad_type']

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

    async def loop_get_peers(self):
        while True:
            try:
                while len(self.info_in_flight) < self.ifl_target:
                    try:
                        ih = self.naked_ihashes.pop()
                    except KeyError:
                        self.cnt['info_naked_hashes_exhausted'] += 1
                        break

                    for i in range(GP_QS_PER_IH):
                        try:
                            nid, sid, addr = self.get_next_nid_sid_addr()
                        except KeyError:
                            self.cnt['info_nodes_exhausted']
                            break

                        if nid in self.info_in_flight:
                            self.cnt['info_node_already_in_ifl']
                            continue

                        self.query_get_peers(sid, ih, addr, prio=False)
                        self.info_in_flight[nid] = (ih, time() + GP_TIMEOUT)
                        self.cnt['info_naked_ih_put_in_ifl'] += 1

            except Exception as e:
                LOG.error(f'Unhandled error in gp loop\n{trc.format_exc()}')
                self.cnt['err_loop_gp_' + e.__class__.__name__] += 1
            
            await asleep(FP_SLEEP)

    async def loop_find_nodes(self):
        '''
        Send out find_node.

        The goal is to inject ourselves into as many node's routing tables
        as possible.
        '''

        while True:
            try:
                if len(self.nodes) < FP_THRESH:
                    for i in range(FP_NUMBER):
                        _, sid, addr = self.get_next_nid_sid_addr()
                        self.query_find_random_node(sid, addr)
                await asleep(FP_SLEEP)
            except (KeyError, IndexError):
                await asleep(FP_SLEEP)
            except Exception as e:
                LOG.warn(f'Unhandled error in fn loop\n{trc.format_exc()}')
                self.cnt[f'err_loop_fn_' + e.__class__.__name__] += 1

    async def loop_purge_ifl(self):
        # wait for more nodes in the pool
        await asleep(5.0)

        while True:
            await asleep(GP_PURGE_TIMER)
            cur_time = time()
            # tread carefully to avoid mutating the dict unatomically,
            try:
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

            except Exception as e:
                LOG.error(f'Unhandled error in purge loop\n{trc.format_exc()}')
                self.cnt[f'err_loop_purge_{e.__class__.__name__}'] += 1

    async def loop_boostrap(self):
        while True:
            if len(self.nodes) < 10:
                for addr in BOOTSTRAP:
                    self.query_find_random_node(rbytes(20), addr)
                LOG.info('Bootstrapped.')
            await asleep(1.0)

    async def loop_save_data(self):
        while True:
            await asleep(60.)
            await self.loop.run_in_executor(None, self.dump_data)
            self._db_conn.commit()
            LOG.info('Saved data.')

    async def loop_control(self):
        '''
        Tracks and dynamically updates parameters controlling the operation
        of the scraper to optimize performance.
        '''
        cnt0 = self.cum_cnt.copy()
        av_gprr = GPRR_TARGET

        await asleep(CONTROL_SECS)
        mark = time()

        while True:
            dcnt = self.cum_cnt - cnt0
            cnt0 = dcnt

            mark += CONTROL_SECS

            await asleep(mark - time())


    async def loop_info(self):

        t_rep = time() + REPORT_SECS
        start = time()
        while True:
            try:
                await asleep(max(t_rep - time(), 0.001))

                LOG.info(
                    'up: {:6.0f} s | '
                    'in: {:3d} p, {:3d} a, '
                    '{:3d}/{:3d} f/r, {:3d}/{:3d} g/r, {:3d} or | '
                    'out: {:3d}/{:3d} f/r, {:3d}/{:3d} g/r, '
                    '{:3d}/{:3d} p/r, {:3d} ar '
                    ' {:3d} db, {:.2f} gprr, {} nids, {} ihs, {} ifl'
                    .format(
                        time() - start,
                        self.cnt['rx_ping'], self.cnt['rx_announce_peer'],
                        self.cnt['rx_find_node'], self.cnt['rx_find_node_r'],
                        self.cnt['rx_get_peers'], self.cnt['rx_get_peers_r'],
                        self.cnt['rx_other_r'],
                        self.cnt['tx_find_node'], self.cnt['tx_find_node_r'],
                        self.cnt['tx_get_peers'], self.cnt['tx_get_peers_r'],
                        self.cnt['tx_ping'], self.cnt['tx_ping_r'],
                        self.cnt['tx_announce_peer_r'],
                        self.cnt['info_db_ih_updates'],
                        self.cnt['rx_get_peers_r'] /
                            (self.cnt['tx_get_peers'] + 1),
                        len(self.nodes), len(self.naked_ihashes),
                        len(self.info_in_flight)
                    )
                )

                self.cum_cnt.update(self.cnt)
                self.cnt.clear()

            except Exception as e:
                self.cnt[f'err_loop_info_{e.__class__.__name__}'] += 1
                LOG.error(f'Unhandled error in info loop\n{trc.format_exc()}')
            finally:
                t_rep = t_rep + REPORT_SECS

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
                for k, v in sorted(self.cum_cnt.items())
                if '_' in k
            ]
        )
        LOG.info('error counts:\n' + s)

    # todo: better persistence format
    def dump_data(self):
        for fn in self.saved_attributes:
            save_pickle(getattr(self, fn), in_data(fn))

    def load_data(self):
        for fn in self.saved_attributes:
            try:
                setattr(self, fn, load_pickle(in_data(fn)))
            except (FileNotFoundError, OSError):
                continue
