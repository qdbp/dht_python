cimport cython

from libc.stdint cimport uint8_t as u8, uint16_t as u16, uint32_t as u32, uint64_t as u64
from libc.stdint cimport int8_t as i8, int16_t as i16, int32_t as i32, int64_t as i64
from libc.string cimport memcmp, memset, memcpy

from dht.stat cimport ST, ST_names

# frequently switched flags
DEF BD_TRACE = 0

# == GENERIC IMMUTABLE
DEF IP_MAX_LEN = 18  # null-terminated

# == KPRC DEFINITIONS
DEF NIH_LEN = 20
DEF IP_LEN = 4
DEF PORT_LEN = 2
DEF PEERINFO_LEN = IP_LEN + PORT_LEN
DEF NODEINFO_LEN = NIH_LEN + PEERINFO_LEN

# our key values
DEF TOKEN = 0x88
DEF TOK = 0x77
DEF MSG_BUF_LEN = 512

# BDECODE SIZES
DEF BD_MAXLEN = 512
DEF BD_MAXLEN_AP_NAME = 256
DEF BD_MAXLEN_TOK = 32
DEF BD_MAXLEN_TOKEN = 32
DEF BD_MAX_PEERS = 36
DEF BD_MAX_NODES = 8

# bdecode message types
DEF MSG_Q_AP = 1
DEF MSG_Q_FN = 1 << 1
DEF MSG_Q_GP = 1 << 2
DEF MSG_Q_PG = 1 << 3
        # R_AP
DEF MSG_R_FN = 1 << 5
DEF MSG_R_GP = 1 << 6
DEF MSG_R_PG = 1 << 7


# MESSAGE LENGTHS
# for computing sids from nids
# d1:ad2:id20: + $nid + 6:target20: + $target + e1:q9:find_node1:t1:\x771:y1:qe
DEF Q_FN_PROTO =\
    b'd1:ad2:id20:' + b'\x11' * 20 +\
    b'6:target20:' + b'\x11' * 20 +\
    b'e1:q9:find_node1:t1:\x771:y1:qe'
DEF Q_FN_LEN = len(Q_FN_PROTO)
# DEF Q_FN_LEN = 12 + 20 + 11 + 20 + 28
DEF Q_FN_SID_OFFSET = 12
DEF Q_FN_TARGET_OFFSET = 43

DEF Q_GP_PROTO =\
    b'd1:ad2:id20:' + b'\x11' * 20 +\
    b'9:info_hash20:' + b'\x11' * 20 +\
    b'5:token1:\x88e1:q9:get_peers1:t1:\x771:y1:qe'
DEF Q_GP_LEN = len(Q_GP_PROTO)
# DEF Q_GP_LEN = 12 + 20 + 14 + 20 + 10 + 28
DEF Q_GP_SID_OFFSET = 12
DEF Q_GP_IH_OFFSET = 46

DEF Q_PG_PROTO = b'd1:ad2:id20:' + b'\x11' * 20 + b'e1:q4:ping1:t1:\x771:y1:qe'
DEF Q_PG_LEN = len(Q_PG_PROTO)
DEF Q_PG_SID_OFFSET = 12

# == SCRAPER CONSTANTS
# info loop
DEF INFO_HEADER_EVERY = 12
DEF TERMINAL_WIDTH = 190

# loop granularities
DEF FP_SLEEP = 0.05
DEF GP_SLEEP = 0.01
DEF PURGE_SLEEP = 0.1
DEF HO_PURGE_SLEEP = 5.0
DEF BOOTSTRAP_SLEEP = 1.0
DEF CONTROL_SLEEP = 1.0
DEF INFO_SLEEP = 5.0
DEF SAVE_SLEEP = 60.0
DEF IH_STAGE_SLEEP = 1.0
DEF IH_DESC_SLEEP = 5.0

# cache sizes and flush intervals
DEF MAX_NODES = 25000
DEF IH_POOL_LEN = 1 << 16
DEF ROW_POOL_MAXLEN = 1000
DEF RECENT_PEER_CACHESIZE = 1 << 20

DEF RTT_BUF_LEN = 1000
DEF DKAD_BUF_LEN = 1000
DEF BULLSHIT_DKAD_THRESH = 80

DEF FP_THRESH = MAX_NODES // 2
DEF FP_NUMBER = 5

DEF BASE_IFL_TARGET = 1000
DEF IFL_TARGET_BACKOFF = 0.95
DEF IFL_TARGET_GROWTH = 5
DEF GPPS_RX_TARGET = 10000
DEF GPPS_RX_MAX = 15000
DEF BASE_IHASH_DISCARD = 0.25
DEF BASE_IHASH_REFRESH = 0.03
DEF BASE_IH_GP_HOLDOFF = 60
DEF BASE_IH_DB_HOLDOFF = 600
DEF BASE_PING_RATE = 0.05
DEF BASE_GP_TIMEOUT = 1.0

DEF DB_FN = b'./data/dht.db'
DEF RT_FN = b'./data/rt.dat'
DEF RT_QUAL_FN = b'./data/rt_qual.dat'
DEF INFO_FILE = b'./live_info.txt'

# rt constants
# DEF RT_CONTACTS_PER_BIN = 256
DEF RT_TOTAL_CONTACTS = 256 * 256 * 256
# rt replace codes
DEF RT_REP_SUCCESS = 1
DEF RT_REP_NO_EVICT = 2
DEF RT_REP_INVALID_NODE = 3
# rt quality settings
DEF MIN_QUAL = 0
DEF MAX_QUAL = 8

DEF META_FLAG_VERIFIED = 1
