from libc.stdint cimport uint8_t as u8, uint64_t as u64, uint16_t as u16

include "dht.pxi"

# XXX the redeclared shit appears to be a cython error and doesn't affect
# functionality... let's hope it goes away
cdef:
    enum bd_status:
        NO_ERROR = 0
        BD_BUFFER_OVERFLOW = 1
        BD_UNEXPECTED_END = 2
        BD_UNEXPECTED_TOKEN = 3
        BD_LIST_IS_KEY = 4
        INCONSISTENT_TYPE = 5
        DICTS_TOO_DEEP = 6
        BAD_LENGTH_PEER = 7
        BAD_LENGTH_NODES = 8
        BAD_LENGTH_IH = 9
        BAD_LENGTH_NID = 10
        BAD_LENGTH_TARGET = 11
        TOK_TOO_LONG = 12
        TOKEN_TOO_LONG = 13
        PORT_OVERFLOW = 14
        UNKNOWN_QUERY = 15
        UNKNOWN_RESPONSE = 16
        NO_NID = 17
        BK_AP_NO_PORT = 18
        BK_APGP_NO_IH = 19
        BK_EMPTY_GP_RESPONSE = 20
        BK_FN_NO_TARGET = 21
        BK_PING_BODY = 22
        NO_TOK = 23
        FALLTHROUGH = 24
        NAKED_VALUE = 25
        ERROR_TYPE = 26
        UNKNOWN_Q = 27
        VALUES_WITHOUT_TOKEN = 28

    enum krpc_msg_type:
        Q_AP = 1
        Q_FN = 1 << 1
        Q_GP = 1 << 2
        Q_PG = 1 << 3
        # R_AP 
        R_FN = 1 << 5
        R_GP = 1 << 6
        R_PG = 1 << 7

    struct parsed_msg:
        # type of message, from among recognized ones
        krpc_msg_type method
        # mandatory fields
        u8 nid[IH_LEN]
        u8 ih[IH_LEN]
        u8 target[IH_LEN]
        # nodes/peers, not all will be set
        u8 tok[BD_MAXLEN_TOK]
        u8 nodes[NODEINFO_LEN * BD_MAX_NODES]
        u8 peers[PEERINFO_LEN * BD_MAX_PEERS]
        u8 token[BD_MAXLEN_TOKEN]
        # number of nodes/peers
        u64 tok_len
        u64 n_nodes
        u64 n_peers
        u64 token_len
        # ap stuff
        u16 ap_port
        bint ap_implied_port

    list g_trace
    dict bd_status_names

cdef bd_status krpc_bdecode(bytes, parsed_msg *)
cdef void print_parsed_msg(parsed_msg *)
