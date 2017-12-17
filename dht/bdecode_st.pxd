from libc.stdint cimport uint8_t as u8, uint64_t as u64, uint16_t as u16

include "dht_h.pxi"

cdef:
    struct parsed_msg:
        # type of message
        u64 method
        # mandatory fields
        u8 nid[NIH_LEN]
        u8 ih[NIH_LEN]
        u8 tok[BD_MAXLEN_TOK]
        u64 tok_len
        # for fn messages
        u8 target[NIH_LEN]
        # nodes/peers, not all will be set
        u8 nodes[NODEINFO_LEN * BD_MAX_NODES]
        u64 n_nodes
        u8 peers[PEERINFO_LEN * BD_MAX_PEERS]
        u64 n_peers
        u8 token[BD_MAXLEN_TOKEN]
        u64 token_len
        # number of nodes/peers
        # ap stuff
        u16 ap_port
        bint ap_implied_port
        u64 ap_name_len
        u8 ap_name[BD_MAXLEN_AP_NAME]

    list g_trace
    dict bd_status_names

cdef u64 krpc_bdecode(bytes, parsed_msg *)
cdef void print_parsed_msg(parsed_msg *)
