'''
Stateless DHT scraper.
'''
from atexit import register as atxreg
import asyncio as aio
from collections import Counter, deque, defaultdict
from functools import lru_cache
from hashlib import sha1
import re
import signal as sig
import socket as sck
import sys
import threading as thr
import traceback as trc
from time import sleep, time
from typing import Dict, Any, Optional, NewType, Tuple, Set, cast

from numpy.random import bytes as rbytes, random

# internal
from .bencode import bencode, bdecode, BdecodeError, BencodeError
from .util import uncompact_addr, uncompact_nodeinfo, uncompact_prefix
from .util import compact_node, compact_addr

from vnv.util import save_pickle, load_pickle
from vnv.log import get_logger
LOG = get_logger(__file__)

Addr = Tuple[bytes, int]

# net: sockets
DHT_LPORT = 56031

# this is a reference node we given when replying to find_peer requests
REF_NODE = (
    b'\xb3\x97\xd6\x06\xa3s{\xa5Q\x03@>\x14P'
    b'\xd4L\xc8\xd6\x99>P\x1f\xc3\xe6A\x9b'
)

TOKEN = b'\x77'

# dht: bootstrap
BOOTSTRAP = [('router.bittorrent.com', 6881)]

# info: global counters
CNT_DISPATCH = 0

CNT_RX_ANNOUNCE_PEER = 0
CNT_RX_ANNOUNCE_PEER_R = 0
CNT_RX_FIND_NODE = 0
CNT_RX_FIND_NODE_R = 0
CNT_RX_GET_PEERS = 0
CNT_RX_GET_PEERS_R = 0
CNT_RX_PING = 0
CNT_RX_OTHER_R = 0

CNT_TX_ANNOUNCE_PEER_R = 0
CNT_TX_FIND_NODE = 0
CNT_TX_FIND_NODE_R = 0
CNT_TX_PING = 0
CNT_TX_PING_R = 0
CNT_TX_GET_PEERS = 0
CNT_TX_GET_PEERS_R = 0

# info: control
REPORT_SECS = 5

MAX_NODES = 1_000_000
GP_TIMEOUT = 30.
GP_PURGE_TIMER = 15.
GP_INIT_RQS = 10

SALT = b'\x13\x37' + int.to_bytes(DHT_LPORT, 2, 'big')

HEUR_PING = re.compile(b'1:y1:r').search
HEUR_NODES = re.compile(b'5:nodes').search
HEUR_TOKEN = re.compile(b'5:token').search


def in_data(fn):
    return '/home/main/programming/python/dht/data/' + fn


@lru_cache(maxsize=1 << 20)
def mk_sid(nid: bytes) -> bytes:
    return nid[:2] + sha1(nid + SALT).digest()[2:]  # type: ignore


def iter_nodes(nodes: bytes):
    for i in range(0, len(nodes), 26):
        yield uncompact_nodeinfo(nodes[i:i + 26])


class DHTScraper:

    saved_attributes = ['nodes', 'info', 'naked_ihashes']

    def __init__(self):
        # == DHT ==
        # info hashes obtained through get_nodes
        # not associated with any nid
        self.naked_ihashes: Set[bytes] = set()

        # info hashes actively being identified
        # indexed by associated addresses; this is onto
        # info_in_flight[addr] = info
        self.info_in_flight: Dict[Addr, Tuple[bytes, float]] = {}
        self.ifl_iter_lock = thr.Lock()

        # plain list of known infohashes
        # info[info_hash] = addr
        self.info: Dict[bytes, Set[Tuple[bytes, Addr]]] =\
            defaultdict(set)

        self.peermap: Dict[bytes, Set[bytes]] = {}
        self.nodes = deque([], maxlen=MAX_NODES)  # type: ignore
        self.talkative_nodes: Set[Tuple[bytes, Addr]] = set()

        self.load_data()

        # TODO
        # complete infos
        # infos that are in the database and should not be rescraped yet
        # self.done_info = set()

        self.cnt: Dict[str, int] = Counter()

        self.send_queue = deque()  # type: ignore
        self.last_sol = 0
        self.do_get_more_nodes = True

        self.dht_sock = sck.socket(sck.AF_INET, sck.SOCK_DGRAM)
        self.dht_sock.bind(('0.0.0.0', DHT_LPORT))
        atxreg(self.dht_sock.close)

        self.loop = aio.get_event_loop()


    def send_msg(self, m, addr):
        '''
        Schedules a message to be sent in FIFO order.

        Sent only if there are no prio messages outstanding.
        '''
        self.send_queue.append((m, addr))

    def send_msg_prio(self, m, addr):
        '''
        Schedules a message to be sent in LIFO order.

        Takes precedence over all non-prio messages irrespective of order.
        '''
        self.send_queue.appendleft((m, addr))

    # TODO: update docstring
    def handle_new_nodes(self, packed_nodes: bytes) -> None:
        '''
        Handles new nodes received message.

        Since we do not store nodes we know, we must always have some
        find_nodes queries in flight, which will trigger this function.
        Since each find_nodes query returns more than one node back
        on average, we can use the extra calls to send get_peers queries.
        '''
        if len(self.nodes) < MAX_NODES - 50000:
            for ix in range(0, len(packed_nodes), 26):
                self.nodes.appendleft(packed_nodes[ix:ix + 26])

    # FIXME implement, document
    def handle_new_peers(self, saddr, resp):
        try:
            ih = self.info_in_flight[saddr][0]
            # FIXME: persistent storage and md lookup
            self.info[ih].update(
                [uncompact_nodeinfo(p) for p in resp[b'values']]
            )
        except TypeError:
            self.cnt['new_peers_bad_values'] += 1
        except KeyError:
            pass
            # FIXME do something more efficient

    def handle_query(self, saddr, msg: Dict[bytes, Any]) ->\
            Optional[Dict[bytes, Any]]:

        global CNT_RX_ANNOUNCE_PEER, CNT_RX_FIND_NODE
        global CNT_RX_GET_PEERS, CNT_RX_PING, CNT_RX_OTHER_R
        global CNT_TX_ANNOUNCE_PEER_R, CNT_TX_PING_R, CNT_TX_GET_PEERS_R
        global CNT_TX_FIND_NODE_R

        token = msg[b't']
        method = msg[b'q']
        args = msg[b'a']
        nid = args[b'id']

        reply: Dict[bytes, Any] = {b'id': mk_sid(nid)}
        reply_msg = {b'y': b'r', b't': token, b'r': reply}

        # FIXME
        if method == b'find_node':
            reply[b'nodes'] = []
            CNT_RX_FIND_NODE += 1
            CNT_TX_FIND_NODE_R += 1

        elif method == b'ping':
            CNT_RX_PING += 1
            CNT_TX_PING_R += 1

        elif method == b'get_peers':
            # ih = args[b'info_hash']
            # if ih not in self.info:
            self.naked_ihashes.add(args[b'info_hash'])

            reply[b'nodes'] = []
            reply[b'token'] = TOKEN

            CNT_RX_GET_PEERS += 1
            CNT_TX_GET_PEERS_R += 1

        elif method == b'announce_peer':
            if args[b'token'] != TOKEN:
                self.cnt['bm_bad_token'] += 1

            if b'implied_port' in args and args[b'implied_port'] == 1:
                p_port = saddr[1]
            else:
                p_port = args[b'port']

            self.info[args[b'info_hash']].add((nid, (saddr[0], p_port)))

            CNT_RX_ANNOUNCE_PEER += 1
            CNT_TX_ANNOUNCE_PEER_R += 1

        else:
            try:
                query_s = method.decode('ascii')
            except UnicodeDecodeError:
                query_s = str(method)

            self.cnt[f'rx_query_{query_s}'] += 1
            return None

        return reply_msg

    def resp_heur(self, d: bytes) -> bool:
        '''
        Tries a quick and dirty heuristic response bypassing bdecode.

        Returns True if the heuristic succeeded, False otherwise.
        '''
        global CNT_RX_FIND_NODE_R
        global CNT_RX_GET_PEERS_R, CNT_RX_OTHER_R
        # use dirty heuristics to avoid bdecode

        # nodes response shortcut
        m_nodes = HEUR_NODES(d)
        if m_nodes and HEUR_TOKEN(d):
            CNT_RX_GET_PEERS_R += 1
            nsix = m_nodes.end()
            # nsix = d.index(b'5:nodes')
            colix = d.index(b':', nsix)
            ns_len = int(d[nsix:colix])
            # not token -> response to find_node
            self.receive_get_peers(d[colix + 1:colix + ns_len + 1])
        # elif HEUR_PING(d):
        #     CNT_RX_OTHER_R += 1
        else:
            return False

        return True

    # FIXME: responses are simple enough to be fully handled by heuristics
    # that are way faster than bdecode
    def handle_response(self, saddr, msg: Dict[bytes, Any]) -> None:
        '''
        Handles a fully bdecoded response dict.

        Slower than the heuristic method, but exact.
        '''
        global CNT_RX_GET_PEERS_R, CNT_RX_FIND_NODE_R, CNT_RX_OTHER_R
        resp = msg[b'r']

        if b'token' in resp:
            CNT_RX_GET_PEERS_R += 1
            # this only gives us closer nodes:
            if b'values' in resp:
                self.handle_new_peers(saddr, resp)
            if b'nodes' in resp:
                # ... first, use throw all the new nodes into the grinder
                self.handle_new_nodes(resp[b'nodes'])
                # ... then, if the query is still active, ask one of
                # the closer nodes
                ih_or_none = self.info_in_flight.get(saddr)
                if ih_or_none is not None:
                    ih = ih_or_none[0]
                    # if we already found this infohash, return
                    if ih in self.info:
                        return
                    for nid, daddr in iter_nodes(resp[b'nodes']):
                        self.query_get_peers(mk_sid(nid), ih, daddr)
                        self.info_in_flight[daddr] = (ih, time() + GP_TIMEOUT)
                        try:
                            del self.info_in_flight[saddr]
                        except KeyError:
                            pass
                        # only query one closer node. If it times out, try
                        # again
                        break

            else:
                self.cnt['bm_token_no_peers_or_nodes'] += 1

        elif b'nodes' in resp:
            CNT_RX_FIND_NODE_R += 1
            for node in resp[b'nodes']:
                self.handle_new_nodes(resp[b'nodes'])

            # XXX use get peers
        else:
            CNT_RX_OTHER_R += 1

    def handle_raw_msg(self, d: bytes, addr) -> None:

        # if self.resp_heur(d):
        #     # RX_PING_R
        #     # RX_GET_PEERS_R
        #     return

        addr = (addr[0].encode(), addr[1])

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
                encoded_reply = bencode(reply_msg)
                self.send_msg_prio(encoded_reply, addr)

        elif msg_type == b'r':
            self.handle_response(addr, msg)

        elif msg_type == b'e':
            # FIXME
            self.cnt['rx_e'] += 1

        else:
            self.cnt['bm_bad_type']

    def query_find_random_node(self, sid, addr):
        '''
        Solicit a new random node based on our current self id and the current
        state
        '''
        global CNT_TX_FIND_NODE
        CNT_TX_FIND_NODE += 1
        msg = (
            b'd1:ad2:id20:' +
            sid +
            b'6:target20:' +
            rbytes(20) +
            b'e1:q9:find_node1:t1:\x771:y1:qe'
        )
        self.send_msg_prio(msg, addr)

    def query_ping_node(self, sid, addr):
        global CNT_TX_PING
        CNT_TX_PING += 1
        msg = b'd1:ad2:id20:' + sid + b'e1:q4:ping1:t1:\x771:y1:qe'
        self.send_msg(msg, addr)

    def query_get_peers(self, sid, info_hash, addr):
        global CNT_TX_GET_PEERS
        CNT_TX_GET_PEERS += 1
        msg = (
            b'd1:ad2:id20:' + sid + b'9:info_hash20:' +
            info_hash + b'5:token1:\x88e1:q9:get_peers1:t1:\x771:y1:qe'
        )
        self.send_msg_prio(msg, addr)

    def bootstrap(self):
        for addr in BOOTSTRAP:
            self.query_find_random_node(rbytes(20), addr)
        LOG.info('Bootstrapped.')

    def recv_loop(self):
        while True:
            try:
                self.handle_raw_msg(*self.dht_sock.recvfrom(1024))
            except (BdecodeError, ValueError, IndexError):
                self.cnt['bm_bdecode_err'] += 1
            except OSError:
                self.cnt['recv_os_err'] += 1
            except Exception:
                LOG.error(f'unhandled error in recv loop\n{trc.format_exc()}')
                self.cnt['recv_unhandled_err'] += 1

    def purge_inflight(self):
        return
        cur_time = time()
        # tread carefully to avoid mutating the dict unatomically,
        to_pop = {
            k for k, v in self.info_in_flight.items()
            if v[1] < cur_time
        }
        for timed_out in to_pop:
            try:
                self.naked_ihashes.add(self.info_in_flight[timed_out][0])
                del self.info_in_flight[timed_out]
            except KeyError:
                continue

        self.loop.call_later(GP_PURGE_TIMER, self.purge_inflight)

    def tx_loop(self):
        while True:
            try:
                while self.send_queue:
                    to = self.send_queue.popleft()
                    self.dht_sock.sendto(*to)
            except OSError:
                self.cnt['tx_oserror'] += 1
            except Exception as e:
                LOG.error(trc.format_exc())
                self.cnt['tx_loop_{}'.format(e.__class__.__name__)] += 1

    def infohash_loop(self):
        while True:
            try:
                if self.naked_ihashes:
                    ih = self.naked_ihashes.pop()
                    nid, addr = uncompact_nodeinfo(self.nodes.pop())
                    sid = mk_sid(nid)
                    self.info_in_flight[addr] = (ih, time() + GP_TIMEOUT)
                    self.query_get_peers(sid, ih, addr)
                else:
                    sleep(0.1)
            except IndexError:
                pass
            except Exception:
                LOG.warn(f'Unhandled error\n{trc.format_exc()}')

    def discovery_loop(self):
        while True:
            try:
                ninfo = self.nodes.pop()
                nid, addr = uncompact_nodeinfo(ninfo)
                sid = mk_sid(nid)
                self.query_find_random_node(sid, addr)
            except IndexError as e:
                self.bootstrap()
                sleep(0.1)
            except Exception as e:
                trc.print_exc()
                self.cnt['dloop_{}'.format(e.__class__.__name__)] += 1

            sleep(0.001)

    def save_data(self):
        self.dump_data()
        self.loop.call_later(60, self.save_data)

    def info_loop(self):
        global CNT_TX_FIND_NODE, CNT_TX_GET_PEERS
        global CNT_TX_FIND_NODE_R, CNT_TX_GET_PEERS_R, CNT_TX_ANNOUNCE_PEER_R
        global CNT_TX_PING, CNT_TX_PING_R, CNT_DISPATCH
        global CNT_RX_ANNOUNCE_PEER, CNT_RX_FIND_NODE
        global CNT_RX_GET_PEERS, CNT_RX_PING
        global CNT_RX_FIND_NODE_R, CNT_RX_GET_PEERS_R, CNT_RX_OTHER_R

        cnt_rx_tot_f = CNT_RX_PING + CNT_RX_ANNOUNCE_PEER + CNT_RX_FIND_NODE +\
            CNT_RX_GET_PEERS
        cnt_rx_tot_r = CNT_RX_OTHER_R + CNT_RX_FIND_NODE_R + CNT_RX_GET_PEERS_R
        cnt_rx_tot = cnt_rx_tot_f + cnt_rx_tot_r

        cnt_tx_tot_f = CNT_TX_PING + CNT_TX_FIND_NODE + CNT_RX_GET_PEERS
        cnt_tx_tot_r = CNT_TX_PING_R + CNT_TX_FIND_NODE_R +\
            CNT_TX_GET_PEERS_R + CNT_TX_ANNOUNCE_PEER_R
        cnt_tx_tot = cnt_tx_tot_f + cnt_tx_tot_r

        t_rep = time() + REPORT_SECS
        start = time()
        while True:
            try:
                sleep(t_rep - time())
                # t = time()
                # ta = t - t_rep + REPORT_SECS
                t_rep = t_rep + REPORT_SECS

                LOG.info(
                    'up: {:6.0f} s | '
                    'in: {:3d} p, {:3d} a, '
                    '{:3d}/{:3d} f/r, {:3d}/{:3d} g/r, {:3d} or | '
                    'out: {:3d}/{:3d} f/r, {:3d}/{:3d} g/r, '
                    '{:3d}/{:3d} p/r, {:3d} ar '
                    ' {} in flight, {} in info'
                    .format(
                        time() - start,
                        CNT_RX_PING, CNT_RX_ANNOUNCE_PEER,
                        CNT_RX_FIND_NODE, CNT_RX_FIND_NODE_R,
                        CNT_RX_GET_PEERS, CNT_RX_GET_PEERS_R,
                        CNT_RX_OTHER_R,
                        CNT_TX_FIND_NODE, CNT_TX_FIND_NODE_R,
                        CNT_TX_GET_PEERS, CNT_TX_GET_PEERS_R,
                        CNT_TX_PING, CNT_TX_PING_R, CNT_TX_ANNOUNCE_PEER_R,
                        CNT_TX_PING, cnt_tx_tot,
                        len(self.info_in_flight), len(self.info)
                    )
                )

                CNT_DISPATCH = 0
                CNT_TX_ANNOUNCE_PEER_R = 0
                CNT_TX_FIND_NODE = CNT_TX_FIND_NODE_R = 0
                CNT_TX_GET_PEERS = CNT_TX_GET_PEERS_R = 0
                CNT_TX_PING = CNT_TX_PING_R = 0
                CNT_RX_ANNOUNCE_PEER = CNT_TX_ANNOUNCE_PEER_R = 0
                CNT_RX_FIND_NODE = CNT_RX_FIND_NODE_R = 0
                CNT_RX_GET_PEERS = CNT_RX_GET_PEERS_R = 0
                CNT_RX_PING = CNT_RX_OTHER_R = 0

            except Exception:
                self.cnt['info_loop_err'] += 1
                LOG.error('unhandled error in info loop\n{}'
                          .format(trc.format_exc()))
                t_rep = t_rep + REPORT_SECS

    def run(self):
        sig.signal(sig.SIGTSTP, self.dump_info)
        self.bootstrap()
        self.t_recv = thr.Thread(
            target=self.recv_loop, name='recv-loop', daemon=True)
        self.t_info = thr.Thread(
            target=self.info_loop, name='info-loop', daemon=True)
        self.t_send = thr.Thread(
            target=self.tx_loop, name='send-loop', daemon=True)
        self.t_disc = thr.Thread(
            target=self.discovery_loop, name='disc-loop', daemon=True)
        self.t_ihash = thr.Thread(
            target=self.infohash_loop, name='ihash-loop', daemon=True)
        self.t_send.start()
        self.t_info.start()
        self.t_recv.start()
        self.t_disc.start()
        self.t_ihash.start()
        self.loop.call_later(15, self.purge_inflight)
        self.loop.call_later(10, self.save_data)
        self.loop.run_forever()
        # self.t_info.join(int(sys.argv[2]) if 'profile' in sys.argv else None)

    def dump_info(self, signum, frame):

        self.cnt['n_naked_ihashes'] = len(self.naked_ihashes)
        self.cnt['n_info_in_flight'] = len(self.info_in_flight)
        self.cnt['n_info'] = len(self.info)
        self.cnt['tx_qsize'] = len(self.send_queue)

        s = '\n'.join(
            [
                (' ' * 15 + '{:>30} : {:<10}'.format(k, v))
                for k, v in sorted(self.cnt.items()) if '_' in k
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
