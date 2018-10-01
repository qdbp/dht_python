#ifndef DHT_BDECODE_H
#define DHT_BDECODE_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dht.h"
#include "stat.h"

// BDECODE SIZES
#define BD_MAXLEN 512
#define BD_MAXLEN_AP_NAME 256
#define BD_MAXLEN_TOK 32
#define BD_MAXLEN_TOKEN 32
#define BD_MAX_PEERS 36
#define BD_MAX_NODES 8

// bdecode message types
typedef enum bd_meth_t {
    MSG_Q_AP = 1u,
    MSG_Q_FN = 1u << 1u,
    MSG_Q_GP = 1u << 2u,
    MSG_Q_PG = 1u << 3u,

    MSG_R_FN = 1u << 5u,
    MSG_R_GP = 1u << 6u,
    MSG_R_PG = 1u << 7u,
} bd_meth_t;

#define BD_IKEY_VALUES 1
#define BD_IKEY_NODES 1 << 1
#define BD_IKEY_TOKEN 1 << 2
#define BD_IKEY_IH 1 << 3
#define BD_IKEY_NID 1 << 4
#define BD_IKEY_TARGET 1 << 5
#define BD_IKEY_IMPLPORT 1 << 6
#define BD_IKEY_PORT 1 << 7
#define BD_IKEY_AP_NAME 1 << 8
#define BD_OKEY_A 1 << 9
#define BD_OKEY_T 1 << 10
#define BD_OKEY_Q 1 << 11
#define BD_OKEY_R 1 << 12
#define BD_OKEY_Y 1 << 13

#define BD_IKEY_ANY_BODY                                            \
    (BD_IKEY_NODES | BD_IKEY_VALUES | BD_IKEY_IH | BD_IKEY_TARGET | \
     BD_IKEY_TOKEN)

#define BD_IKEY_ANY_NON_TOKEN_BODY \
    (BD_IKEY_NODES | BD_IKEY_VALUES | BD_IKEY_IH | BD_IKEY_TARGET)

#define R_ANY (MSG_R_FN | MSG_R_GP | MSG_R_PG)
#define Q_ANY (MSG_Q_AP | MSG_Q_FN | MSG_Q_GP | MSG_Q_PG)

typedef struct parsed_msg {
    // type of message;
    bd_meth_t method;
    // mandatory fields;
    char nid[NIH_LEN];
    char ih[NIH_LEN];
    char tok[BD_MAXLEN_TOK];
    u64 tok_len;
    // for fn messages;
    char* target[NIH_LEN];
    // nodes / peers, not all will be set;
    char nodes[NODEINFO_LEN * BD_MAX_NODES];
    u64 n_nodes;
    char peers[PEERINFO_LEN * BD_MAX_PEERS];
    u64 n_peers;
    char token[BD_MAXLEN_TOKEN];
    u64 token_len;
    // number of nodes / peers;
    // ap stuff;
    u16 ap_port;
    bool ap_implied_port;
    u64 ap_name_len;
    char ap_name[BD_MAXLEN_AP_NAME];
} parsed_msg;

typedef struct bd_state {
    u64 fail;
    int dict_depth;
    int list_depth;
    bool at_end;
    // set when we find a key, expecting a particular value
    // set during the reading_dict_key phase
    bool reading_dict_key;
    u64 current_key;
    u64 seen_keys;
    // u64 legal_kinds
    bd_meth_t msg_kind;
    bool save_ap_port;
    bool is_response;
    u64 method;
} bd_state;

typedef void (*bdecode_fn_t)(const char*, u64*, u64, bd_state*, parsed_msg*);

void krpc_bdecode_dispatch(const char*, u64*, u64, bd_state*, parsed_msg*);
stat_t krpc_bdecode(const char*, u64, parsed_msg*);
void bd_init(void);

void print_parsed_msg(parsed_msg*);
const char* get_method_name(bd_meth_t);

// bdecode_fn_t krpc_bdecode_d;
// bdecode_fn_t krpc_bdecode_e;
// bdecode_fn_t krpc_bdecode_i;
// bdecode_fn_t krpc_bdecode_s;
// bdecode_fn_t krpc_bdecode_fail;
// bdecode_fn_t krpc_bdecode_l;

#endif  // DHT_BDECODE_H
