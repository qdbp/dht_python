#include <uv.h>
#include "msg.h"

#define OUR_TOK "\x77"
#define OUR_TOKEN "\x88"

const char Q_FN_PROTO[] =
    "d1:ad2:id20:"
    "\x0\x0\x0\x0\x0"
    "\x0\x0\x0\x0\x0"
    "\x0\x0\x0\x0\x0"
    "\x0\x0\x0\x0\x0"
    "6:target20:"
    "\x0\x0\x0\x0\x0"
    "\x0\x0\x0\x0\x0"
    "\x0\x0\x0\x0\x0"
    "\x0\x0\x0\x0\x0"
    "e1:q9:find_node1:t1:" OUR_TOK "1:y1:qe";

#define Q_FN_LEN (sizeof(Q_FN_PROTO) - 1)
// #define Q_FN_LEN 12 + 20 + 11 + 20 + 28
#define Q_FN_SID_OFFSET 12
#define Q_FN_TARGET_OFFSET 43

const char Q_GP_PROTO[] =
    "d1:ad2:id20:"
    "\x0\x0\x0\x0\x0"
    "\x0\x0\x0\x0\x0"
    "\x0\x0\x0\x0\x0"
    "\x0\x0\x0\x0\x0"
    "9:info_hash20:"
    "\x0\x0\x0\x0\x0"
    "\x0\x0\x0\x0\x0"
    "\x0\x0\x0\x0\x0"
    "\x0\x0\x0\x0\x0"
    "5:token1:" OUR_TOKEN "e1:q9:get_peers1:t1:" OUR_TOK "1:y1:qe";

#define Q_GP_LEN (sizeof(Q_GP_PROTO) - 1)
#define Q_GP_SID_OFFSET 12
#define Q_GP_IH_OFFSET 46

const char Q_PG_PROTO[] =
    "d1:ad2:id20:"
    "\x0\x0\x0\x0\x0"
    "\x0\x0\x0\x0\x0"
    "\x0\x0\x0\x0\x0"
    "\x0\x0\x0\x0\x0"
    "e1:q4:ping1:t1:" OUR_TOK "1:y1:qe";

#define Q_PG_LEN (sizeof(Q_PG_PROTO) - 1)
#define Q_PG_SID_OFFSET 12

#define APPEND(dst, offset, strlit)                   \
    memcpy(dst + offset, strlit, sizeof(strlit) - 1); \
    offset += sizeof(strlit) - 1;

inline void write_sid(char* dst, const char nid[]) {
    static const char mask[] = "\0\0\0SUBMITTOTHESCRAPE";
    memcpy(dst, nid, 3);
    for (int ix = 3; ix < NIH_LEN; ix++) {
        dst[ix] = nid[ix] ^ mask[ix];
    }
}

u64 msg_q_gp(char* dst, const rt_nodeinfo_t* dest, const char* infohash) {
    memcpy(dst, Q_GP_PROTO, Q_GP_LEN);
    memcpy(dst + Q_GP_IH_OFFSET, infohash, NIH_LEN);
    write_sid(dst + Q_GP_SID_OFFSET, dest->nid);

    return Q_GP_LEN;
}

u64 msg_q_fn(char* dst, const rt_nodeinfo_t* dest, const char* target) {
    memcpy(dst, Q_FN_PROTO, Q_FN_LEN);
    memcpy(dst + Q_FN_TARGET_OFFSET, target, NIH_LEN);
    write_sid(dst + Q_FN_SID_OFFSET, dest->nid);

    return Q_FN_LEN;
}

u64 msg_q_pg(char* dst, char* nid) {
    memcpy(dst, Q_PG_PROTO, Q_PG_LEN);
    write_sid(dst + Q_PG_SID_OFFSET, nid);

    return Q_PG_LEN;
}

u64 msg_r_fn(char* dst, const parsed_msg* rcvd, const rt_nodeinfo_t* pnode) {
    u64 offset = 0;

    APPEND(dst, offset, "d1:rd2:id20:")

    write_sid(dst + offset, rcvd->nid);
    offset += NIH_LEN;

    APPEND(dst, offset, "5:nodes26:")

    write_nodeinfo(dst + offset, pnode);
    offset += NODEINFO_LEN;

    APPEND(dst, offset, "e1:t")

    memcpy(dst + offset, rcvd->tok, rcvd->tok_len);
    offset += rcvd->tok_len;

    APPEND(dst, offset, "1:y1:re")

    return offset;
}

u64 msg_r_gp(char* dst, const parsed_msg* rcvd, const rt_nodeinfo_t* pnode) {
    u64 offset = 0;

    APPEND(dst, offset, "d1:rdl:id20:")

    write_sid(dst, rcvd->nid);
    offset += NIH_LEN;

    APPEND(dst, offset, "5:token1:" OUR_TOKEN "5:nodes26:")

    write_nodeinfo(dst + offset, pnode);
    offset += NODEINFO_LEN;

    APPEND(dst, offset, "e1:t")

    memcpy(dst + offset, rcvd->tok, rcvd->tok_len);
    offset += rcvd->tok_len;

    APPEND(dst, offset, "1:y1:re")

    return offset;
}

u64 msg_r_pg(char* dst, const parsed_msg* rcvd) {
    u64 offset = 0;

    APPEND(offset, dst, "d1:rd2:id20:")

    write_sid(dst + offset, rcvd->nid);
    offset += NIH_LEN;

    APPEND(offset, dst, "e1:t")

    memcpy(dst + offset, rcvd->tok, rcvd->tok_len);
    offset += rcvd->tok_len;

    APPEND(dst, offset, "1:y1:re");

    return offset;
}
