#include "bdecode.h"
#include "log.h"

const char keyname_NID[] = "id";
const char keyname_PORT[] = "port";
const char keyname_NODES[] = "nodes";
const char keyname_TOKEN[] = "token";
const char keyname_TARGET[] = "target";
const char keyname_VALUES[] = "values";
const char keyname_IH[] = "info_hash";
const char keyname_IMPLPORT[] = "implied_port";
const char keyname_AP_NAME[] = "name";

const char valname_AP[] = "announce_peer";
const char valname_GP[] = "get_peers";
const char valname_FN[] = "find_node";
const char valname_PG[] = "ping";

#define BD_KEY_MATCH(ptr, slen, keyname)          \
    ((slen == (sizeof(keyname_##keyname) - 1)) && \
     (0 == memcmp(ptr, keyname_##keyname, slen)))
#define BD_VAL_MATCH(ptr, slen, keyname)          \
    ((slen == (sizeof(valname_##keyname) - 1)) && \
     (0 == memcmp(ptr, valname_##keyname, slen)))

#ifdef BD_TRACE
#define TRACE(msg, ...) DEBUG(msg, ##__VA_ARGS__)
#else
#define TRACE(msg, ...)  // nothing
#endif

#define FAIL_MSG(state_ptr, code, msg) \
    (state_ptr)->fail = (code);        \
    TRACE("FAIL: " #code msg);         \
    return;
#define FAIL(state_ptr, code) FAIL_MSG((state_ptr), (code), "")

static inline i64 krpc_bdecode_atoi(const char* buf,
                                    u64* ix,
                                    u64 maxlen,
                                    bd_state* state) {
    /*
    Decode strictly nonnegative, colon-terminated decimal integers. Fast.

    Is stateful: xdvances the buffer index in-place. Advances the index
    an extra position on returning, thus consuming the termination symbol.
    */

    i64 out = 0;
    i64 sign = 1;

    if (ix[0] < maxlen && buf[ix[0]] == 45) {
        sign = -1;
        ix[0] += 1;
    }

    // ord(decimal_digit) = decimal_digit + 48
    while (ix[0] < maxlen && 48 <= buf[ix[0]] && buf[ix[0]] < 58) {
        out = 10 * out + buf[ix[0]] - 48;
        ix[0] += 1;
    }

    // consume the position of the b ':' or b 'e'
    ix[0] += 1;

    // the previous tests failed because of overflow iff ix[0] = maxlen + 1
    // here therefore this test passes iff not overflow
    if (ix[0] > maxlen) {
        state->fail = ST_bd_x_msg_too_long;
    }

    return out * sign;
}

static inline void krpc_bdecode_i(const char* data,
                                  u64* ix,
                                  u64 maxlen,
                                  bd_state* state,
                                  parsed_msg* out) {
    i64 result;

    ix[0] += 1;
    result = krpc_bdecode_atoi(data, ix, maxlen, state);

    if (state->save_ap_port) {
        TRACE("saving port")
        if (result < (1 << 16)) {
            out->ap_port = (u16)result;
        } else {
            FAIL(state, ST_bd_y_port_overflow)
        }
    }
}

static void krpc_bdecode_s(const char* data,
                           u64* ix,
                           u64 maxlen,
                           bd_state* state,
                           parsed_msg* out) {
    /*
    The most important krpc_bdecode function, since this is the only one that
    actually extracts useful data (which is all strings).

    The state setup by other functions was for the benefit of krpc_bdecode_s.

    This is a lovable monstrosity. Be delicate with it. If you don't know what
    something does, think 7 times before changing it, or you will feel pain.
    */
    i64 slen, start;

    slen = krpc_bdecode_atoi(data, ix, maxlen, state);
    // if overflow, unwind instantly
    if (state->fail != ST_bd_a_no_error) {
        return;
    }

    start = *ix;

    // if reading the string would overflow, set the fail flag and unwind
    if (maxlen < start + slen) {
        TRACE("maxlen: %d, start: %d, slen: %d", maxlen, start, slen)
        FAIL(state, ST_bd_x_msg_too_long)
    }

    *ix += slen;

#ifdef BD_TRACE
    char msg[256] = {};
    char string[256] = {};
    TRACE("parsing string, [rk = %d][dict depth = %d][list depth = %d]",
          state->reading_dict_key, state->dict_depth, state->list_depth)
#endif

    if (state->reading_dict_key) {
        // reset some flags on a new key
        state->save_ap_port = 0;
        state->current_key = 0;

        switch (state->dict_depth) {
            case 0:
                FAIL(state, ST_bd_y_naked_value)
                break;
            case 1:
                TRACE(">>> reading key of depth 1")
                // all outer keys have length 1, can check it off the bat
                if (slen != 1) {
                    TRACE("??? got bad okey '%.*s' [slen != 1], ignoring it",
                          slen, data + start)
                    break;
                }
                switch (data[start]) {
                    case 'a':
                        if (state->seen_keys & BD_OKEY_R) {
                            FAIL(state, ST_bd_y_inconsistent_type)
                        }
                        TRACE(">>> matched okey 'a'")
                        // state->legal_kinds &= Q_ANY
                        state->msg_kind &= Q_ANY;
                        state->current_key = BD_OKEY_A;
                        state->seen_keys |= BD_OKEY_A;
                        break;
                    case 'r':
                        if (state->seen_keys & (BD_OKEY_A | BD_OKEY_Q)) {
                            FAIL(state, ST_bd_y_inconsistent_type)
                        }
                        TRACE(">>> matched okey 'r'");
                        state->msg_kind &= R_ANY;
                        state->current_key = BD_OKEY_R;
                        state->seen_keys |= BD_OKEY_R;
                        break;
                    case 't':
                        TRACE(">>> matched okey 't'")
                        state->current_key = BD_OKEY_T;
                        state->seen_keys |= BD_OKEY_T;
                        break;
                    case 'q':
                        if (state->seen_keys & BD_OKEY_R) {
                            FAIL(state, ST_bd_y_inconsistent_type)
                        }
                        TRACE(">>> matched okey 'q'")
                        state->msg_kind &= Q_ANY;
                        state->current_key = BD_OKEY_Q;
                        state->seen_keys |= BD_OKEY_Q;
                        break;
                    case 'y':
                        TRACE(">>> matched okey 'y'")
                        state->current_key = BD_OKEY_Y;
                        state->seen_keys |= BD_OKEY_Y;
                        break;
                    default:
                        TRACE("??? matched unknown okey, ignoring it")
                        break;
                }
                break;
                // READ KEYS DEPTH 2
            case 2:
                TRACE(">>> reading key of depth 2")
                if (BD_KEY_MATCH(data + start, slen, NID)) {
                    TRACE(">>> matched ikey ID; * -> *")
                    state->current_key = BD_IKEY_NID;
                    state->seen_keys |= BD_IKEY_NID;

                } else if (BD_KEY_MATCH(data + start, slen, IH)) {
                    TRACE(">>> matched ikey INFO_HASH; * -> MSG_Q_AP|MSG_Q_GP")
                    state->msg_kind &= (MSG_Q_GP | MSG_Q_AP);
                    state->current_key = BD_IKEY_IH;
                    state->seen_keys |= BD_IKEY_IH;

                } else if (BD_KEY_MATCH(data + start, slen, NODES)) {
                    TRACE(">>> matched ikey NODES; * -> MSG_R_FN|MSG_R_GP")
                    state->msg_kind &= (MSG_R_FN | MSG_R_GP);
                    state->current_key = BD_IKEY_NODES;
                    state->seen_keys |= BD_IKEY_NODES;

                } else if (BD_KEY_MATCH(data + start, slen, VALUES)) {
                    TRACE(">>> matched ikey VALUES; * -> MSG_R_GP")
                    state->msg_kind &= MSG_R_GP;
                    state->current_key = BD_IKEY_VALUES;
                    state->seen_keys |= BD_IKEY_VALUES;

                } else if (BD_KEY_MATCH(data + start, slen, TOKEN)) {
                    TRACE(">>> matched ikey TOKEN; X -> X & ~MSG_R_FN")
                    // NOTE many random queries include a token, we allow for it
                    // quite broadly
                    state->msg_kind &= (~MSG_Q_FN);
                    state->current_key = BD_IKEY_TOKEN;
                    state->seen_keys |= BD_IKEY_TOKEN;
                } else if (BD_KEY_MATCH(data + start, slen, TARGET)) {
                    TRACE(">>> matched ikey TARGET; * -> MSG_Q_FN")
                    state->msg_kind &= MSG_Q_FN;
                    state->current_key = BD_IKEY_TARGET;
                    state->seen_keys |= BD_IKEY_TARGET;
                } else if (BD_KEY_MATCH(data + start, slen, PORT)) {
                    TRACE(">>> matched ikey PORT")
                    // we do not restrict the legal kinds, since other
                    // messages can have a port as extra data we ignore
                    state->seen_keys |= BD_IKEY_PORT;
                    state->save_ap_port = 1;
                } else if (BD_KEY_MATCH(data + start, slen, IMPLPORT)) {
                    TRACE(">>> matched ikey IMPLIED_PORT; * -> MSG_Q_AP")
                    state->msg_kind &= MSG_Q_AP;
                    state->current_key = BD_IKEY_IMPLPORT;
                    state->seen_keys |= BD_IKEY_IMPLPORT;
                } else if (BD_KEY_MATCH(data + start, slen, AP_NAME)) {
                    // ignore name field in non - announce peer messages
                    if (state->msg_kind & MSG_Q_AP) {
                        TRACE(">>> matched ikey NAME; &MSG_Q_AP -> MSG_Q_AP")
                        state->msg_kind = MSG_Q_AP;
                        state->current_key = BD_IKEY_AP_NAME;
                        state->seen_keys |= BD_IKEY_AP_NAME;
                    }
                } else {
                    TRACE("Hit an unknown internal key '%.*s', ignoring", slen,
                          data + start)
                }
                break;
            default:
                FAIL(state, ST_bd_z_dicts_too_deep)
                break;
        }
        // READ VALUES
    } else {
        switch (state->dict_depth) {
            default:
                FAIL(state, ST_bd_z_dicts_too_deep)
                break;
            case 1:
                TRACE(">>> reading values, depth 1")
                switch (state->current_key) {
                    // set the query type, if one is found...
                    case BD_OKEY_Q:
                        if (BD_VAL_MATCH(data + start, slen, AP)) {
                            TRACE("!!! q is MSG_Q_AP")
                            state->msg_kind &= MSG_Q_AP;
                        } else if (BD_VAL_MATCH(data + start, slen, FN)) {
                            TRACE("!!! q is MSG_Q_FN")
                            state->msg_kind &= MSG_Q_FN;
                        } else if (BD_VAL_MATCH(data + start, slen, GP)) {
                            TRACE("!!! q is MSG_Q_GP")
                            state->msg_kind &= MSG_Q_GP;
                        } else if (BD_VAL_MATCH(data + start, slen, PG)) {
                            TRACE("!!! q is MSG_Q_PG")
                            state->msg_kind &= MSG_Q_PG;
                        } else {
                            FAIL(state, ST_bd_z_unknown_query)
                        }
                        break;
                    // set the token
                    case BD_OKEY_T:
                        if (slen > BD_MAXLEN_TOK) {
                            FAIL(state, ST_bd_z_tok_too_long)
                        }
                        TRACE("!!! TOK[%lu] = '%.*s'", slen, slen,
                              data + start);
                        out->tok_len = slen;
                        memcpy(out->tok, data + start, slen);
                        break;
                    // check response consistency
                    case BD_OKEY_Y:
                        break;
                        if (slen == 1) {
                            switch (data[start]) {
                                case 'e':
                                    FAIL(state, ST_bd_z_error_type)
                                    break;
                                case 'r':
                                    state->msg_kind &= R_ANY;
                                    break;
                                case 'q':
                                    state->msg_kind &= Q_ANY;
                                    break;
                                default:
                                    FAIL(state, ST_bd_z_unknown_type)
                                    break;
                            }
                        } else {
                            FAIL(state, ST_bd_z_unknown_type)
                        }
                    // ignore other cases
                    // TODO add better logic?
                    default:
                        break;
                }
                break;
            case 2:  // state->dict_depth
                TRACE(">>> read values, depth 2")
                // within a list, we expect only value strings
                switch (state->current_key) {
                    case BD_IKEY_VALUES:
                        if (state->list_depth == 1) {
                            // we are in a values list, but we read a weird
                            // string NOTE we assume the entire message is
                            // corrupted and bail out, parsing very
                            // conservatively is the key to sanity
                            if (slen != PEERINFO_LEN) {
                                FAIL(state, ST_bd_y_bad_length_peer)
                            }
                            if (out->n_peers < BD_MAX_PEERS) {
                                memcpy(
                                    out->peers + (PEERINFO_LEN * out->n_peers),
                                    data + start, PEERINFO_LEN);
                            }
                            out->n_peers += 1;
                            TRACE("!!! VALUES[%d]", slen / PEERINFO_LEN)
                        }
                        break;
                    case BD_IKEY_NODES:
                        if ((slen == 0) || ((slen % NODEINFO_LEN) != 0)) {
                            FAIL(state, ST_bd_y_bad_length_nodes)
                        }
                        if (slen > (NODEINFO_LEN * BD_MAX_NODES)) {
                            TRACE(">>> truncating nodes list")
                            slen = NODEINFO_LEN * BD_MAX_NODES;
                        }
                        TRACE("!!! NODES[%d]", slen / NODEINFO_LEN);
                        out->n_nodes = slen / NODEINFO_LEN;
                        memcpy(out->nodes, data + start, slen);
                        break;
                    case BD_IKEY_TOKEN:
                        if (slen > BD_MAXLEN_TOKEN) {
                            FAIL(state, ST_bd_z_token_too_long)
                        }
                        TRACE("!!! TOKEN[%lu] = ...", slen);
                        memcpy(out->token, data + start, slen);
                        out->token_len = slen;
                        break;
                    case BD_IKEY_TARGET:
                        if (slen != NIH_LEN) {
                            FAIL(state, ST_bd_y_bad_length_target)
                        }
                        TRACE("!!! TARGET = ...")
                        memcpy(out->target, data + start, slen);
                        break;
                    case BD_IKEY_NID:
                        if (slen != NIH_LEN) {
                            FAIL(state, ST_bd_y_bad_length_nid)
                        }
                        TRACE("!!! NID")
                        memcpy(out->nid, data + start, slen);
                        break;
                    case BD_IKEY_IH:
                        if (slen != NIH_LEN) {
                            FAIL(state, ST_bd_y_bad_length_ih)
                        }
                        TRACE("!!! IH")
                        memcpy(out->ih, data + start, slen);
                        break;
                    case BD_IKEY_AP_NAME:
                        if (slen > BD_MAXLEN_AP_NAME) {
                            TRACE("??? AP_NAME too long, ignoring.")
                        } else {
#ifdef BD_TRACE
                            char msg[512] = {0};
                            char ap_name[256] = {0};
                            strncat(ap_name, data + start, slen);
                            snprintf(msg, 512, "!!! TOKEN[%lu] = [%s]...", slen,
                                     ap_name);
                            TRACE("%s", msg)
#endif
                            memcpy(out->ap_name, data + start, slen);
                            out->ap_name_len = slen;
                        }
                        break;
                    // ignore other keys
                    default:
                        break;
                }
        }
        // switch(state->dict_depth)
    }
}

static inline void krpc_bdecode_l(const char* data,
                                  u64* ix,
                                  u64 maxlen,
                                  bd_state* state,
                                  parsed_msg* pmsg) {
    // lists cannot be keys, fail instantly
    if (state->reading_dict_key) {
        FAIL(state, ST_bd_x_list_is_key)
    }

    *ix += 1;
    state->list_depth += 1;

    do {
        krpc_bdecode_dispatch(data, ix, maxlen, state, pmsg);
        // on fail, unwind the stack and gtfo
        if (state->fail != ST_bd_a_no_error) {
            TRACE("unwinding failure")
            return;
        }
        // if we read the end, reset the end flag and the in - list marker
        if (state->at_end) {
            TRACE("got end of list")
            state->at_end = 0;
            state->list_depth -= 1;
            return;
        }
    } while (1);
}

static inline void krpc_bdecode_d(const char* data,
                                  u64* ix,
                                  u64 maxlen,
                                  bd_state* state,
                                  parsed_msg* out) {
    *ix += 1;
    state->dict_depth += 1;

    do {
        // read the key, as a key
        state->reading_dict_key = 1;
        krpc_bdecode_dispatch(data, ix, maxlen, state, out);

        if (state->fail != ST_bd_a_no_error) {
            TRACE("unwinding dict key failure")
            return;
        }
        // if instead of a key we read the end, we unwind a level of
        // dict, and reset the end flag
        if (state->at_end) {
            TRACE("got end of dict")
            state->at_end = 0;
            state->dict_depth -= 1;
            return;
        }
        // read the value
        state->reading_dict_key = 0;
        krpc_bdecode_dispatch(data, ix, maxlen, state, out);
        // it is an error to read end as a key
        if (state->fail != ST_bd_a_no_error) {
            TRACE("unwinding dict value failure")
            return;
        }
        if (state->at_end) {
            FAIL(state, ST_bd_x_bad_eom)
        }
    } while (1);
}

static inline void krpc_bdecode_fail(const char* data,
                                     u64* ix,
                                     u64 maxlen,
                                     bd_state* state,
                                     parsed_msg* out) {
    FAIL(state, ST_bd_x_bad_char)
}

static inline void krpc_bdecode_e(const char* data,
                                  u64* ix,
                                  u64 maxlen,
                                  bd_state* state,
                                  parsed_msg* out) {
    state->at_end = 1;
    *ix += 1;
    return;
}

static bdecode_fn_t g_krpc_dispatch_table[256];

void bd_init(void) {
    for (int ix = 0; ix < 0x100; ix += 1) {
        g_krpc_dispatch_table[ix] = &krpc_bdecode_fail;
    }
    for (int ix = 0x30; ix < 0x40; ix += 1) {
        g_krpc_dispatch_table[ix] = &krpc_bdecode_s;
    }

    g_krpc_dispatch_table['d'] = &krpc_bdecode_d;
    g_krpc_dispatch_table['e'] = &krpc_bdecode_e;
    g_krpc_dispatch_table['i'] = &krpc_bdecode_i;
    g_krpc_dispatch_table['l'] = &krpc_bdecode_l;
    g_krpc_dispatch_table['s'] = &krpc_bdecode_s;
}

inline void krpc_bdecode_dispatch(const char* data,
                                  u64* ix,
                                  u64 maxlen,
                                  bd_state* state,
                                  parsed_msg* out) {
    if (*ix < maxlen) {
        g_krpc_dispatch_table[(int)data[*ix]](data, ix, maxlen, state, out);
    } else {
        FAIL(state, ST_bd_x_msg_too_long)
    }
    return;
}

stat_t krpc_bdecode(const char* data, u64 data_len, parsed_msg* out) {
    /*
    Efficiently decodes a KRPC message, looking for pre-existing fields,
    into a fixed parsed_msg structure.

    Returns 1 if the parse was successful, 0 otherwise.

    If 0 is returned, the output structure should NOT BE USED IN ANY WAY,
    since it is not guaranteed to be consistent, or even wholly initialized,
    in the case of a parse failure.
    */

    u64 chunk_offset = 0;
    char* buf[BD_MAXLEN];

    // complete initialization of the state struct
    bd_state state = {
        .fail = ST_bd_a_no_error,
        .dict_depth = 0,
        .list_depth = 0,
        .at_end = false,

        .reading_dict_key = false,
        .current_key = 0,
        .seen_keys = 0,

        .msg_kind = 0xffffffff,
        .save_ap_port = false,
        .is_response = true,
    };

    if (data_len > BD_MAXLEN) {
        state.fail = ST_bd_x_msg_too_long;
        return state.fail;
    } else {
        memcpy(buf, data, data_len);
    }

    out->n_nodes = out->n_peers = 0;
    out->tok_len = out->token_len = out->ap_name_len = 0;

    // this is where the magic happens! After this call our state and
    // parsed_msg structures are filled in
    krpc_bdecode_dispatch((const char*)buf, &chunk_offset, BD_MAXLEN, &state,
                          out);

    if (state.fail != ST_bd_a_no_error) {
        return state.fail;
    }

    // MESSAGE SANITY FILTERING
    // ALL messages need a NID...
    if (!(state.seen_keys & BD_IKEY_NID)) {
        return ST_bd_y_no_nid;
    }

    //... and a TOK
    if (!(state.seen_keys & BD_OKEY_T)) {
        return ST_bd_y_no_tok;
    }

#ifdef BD_TRACE
    char msg[256];
    snprintf(msg, 256, "??? DECIDING: [keys = %lu] [methods = %lu]",
             state.seen_keys, state.msg_kind);
    TRACE("%s", msg)
#endif

    // METHOD RESOLUTION
    // exact APs and GPs need an info_hash only
    if (state.msg_kind & Q_ANY) {
        TRACE("??? DECIDING as query")
        if (state.msg_kind == MSG_Q_AP || state.msg_kind == MSG_Q_GP) {
            if (!(state.seen_keys & BD_IKEY_IH)) {
                TRACE("=== REJECT (q_gp | q_ap) && ~ih")
                return ST_bd_y_apgp_no_ih;
            } else if (state.msg_kind == MSG_Q_AP &&
                       !(state.seen_keys & (BD_IKEY_PORT | BD_IKEY_IMPLPORT))) {
                TRACE("=== REJECT q_ap && ~(port | impl_port)")
                return ST_bd_y_ap_no_port;
            }
#ifdef BD_TRACE
            if (state.msg_kind == MSG_Q_AP) {
                TRACE("=== ACCEPT MSG_Q_AP")
            } else {
                TRACE("=== ACCEPT MSG_Q_GP")
            }
#endif
            out->method = state.msg_kind;
        } else if (state.msg_kind == MSG_Q_FN) {
            if (!(state.seen_keys & BD_IKEY_TARGET)) {
                TRACE("=== REJECT q_fn && ~target")
                return ST_bd_y_fn_no_target;
            }
            TRACE("=== ACCEPT MSG_Q_FN")
            out->method = MSG_Q_FN;
        }
        // accept only simple pings
        else if (state.msg_kind == MSG_Q_PG) {
            if (state.seen_keys & BD_IKEY_ANY_BODY) {
                TRACE("=== REJECT q_pg && body")
                return ST_bd_z_ping_body;
            }
            TRACE("=== ACCEPT MSG_Q_PG")
            out->method = MSG_Q_PG;
        } else {
            TRACE("=== REJECT fallthrough q_any")
            return ST_bd_z_unknown_query;
        }
    } else if (state.msg_kind & R_ANY) {
        TRACE("??? DECIDING as reply")
        // TOKEN and (VALUES or NODES) <-> R_GP
        if ((state.seen_keys & BD_IKEY_TOKEN) &&
            state.seen_keys & (BD_IKEY_VALUES | BD_IKEY_NODES)) {
            TRACE("??? DECIDING as R_GP")
            out->method = MSG_R_GP;

            if (out->n_nodes + out->n_peers == 0) {
                TRACE("=== REJECT r_gp && (n + v) == 0")
                return ST_bd_y_empty_gp_response;
            }
            TRACE("=== ACCEPT token && (nodes | values) -> MSG_R_GP")
        }
        // VALUES and ~TOKEN <-> bad R_GP
        else if ((state.seen_keys & BD_IKEY_VALUES) &&
                 !(state.seen_keys & BD_IKEY_TOKEN)) {
            TRACE("=== REJECT values && ~token")
            return ST_bd_y_vals_wo_token;
        }
        //~TOKEN and ~VALUES and NODES <->R_FN
        else if (state.seen_keys & BD_IKEY_NODES) {
            TRACE("=== ACCEPT ~token && ~values && nodes -> MSG_R_FN")
            out->method = MSG_R_FN;
        }
        //~NODES and ~VALUES <->R_PG
        else {
            if (state.seen_keys & BD_IKEY_ANY_NON_TOKEN_BODY) {
                TRACE(
                    "=== REJECT (body - tok) && ~(nodes || values) -> bad r_pg")
                return ST_bd_z_ping_body;
            }
            TRACE("=== ACCEPT ~(values | nodes) -> MSG_R_PG")
            out->method = MSG_R_PG;
        }
    } else {
        TRACE("=== REJECT ~[type & (q | r)] -> incongruous")
        return ST_bd_z_incongruous_message;
    }

    return ST_bd_a_no_error;
}

inline const char* get_method_name(bd_meth_t method) {
    switch (method) {
        case MSG_R_GP:
            return "MSG_R_GP";
        case MSG_R_PG:
            return "MSG_R_PG";
        case MSG_R_FN:
            return "MSG_R_FN";
        case MSG_Q_AP:
            return "MSG_Q_AP";
        case MSG_Q_GP:
            return "MSG_Q_GP";
        case MSG_Q_FN:
            return "MSG_Q_FN";
        case MSG_Q_PG:
            return "MSG_Q_PG";
        default:
            return "No such method!";
    }
}

void print_parsed_msg(parsed_msg* out) {
    printf("\tMETH = %s\n", get_method_name(out->method));

    char tok_buf[BD_MAXLEN_TOK + 1];
    strncat(tok_buf, (const char*)out->tok, BD_MAXLEN_TOK + 1);
    printf("\tTOK[%lu] = %s\n", out->tok_len, tok_buf);

    char nid_buf[21];
    strncat(nid_buf, (const char*)out->nid, 21);
    printf("\tNID[20] = %s\n", nid_buf);

    if (out->method == MSG_Q_AP) {
        char ih_buf[21];
        strncat(ih_buf, (const char*)out->ih, 21);
        printf("\t\tMSG_Q_AP -> IH = %s\n", ih_buf);

        printf("\t\tMSG_Q_AP -> PORT = {%hu} (IP = {%i})\n", out->ap_port,
               out->ap_implied_port);

        char token_buf[BD_MAXLEN_TOKEN + 1];
        strncat(token_buf, (const char*)out->token, BD_MAXLEN_TOKEN + 1);
        printf("\t\tMSG_Q_AP -> TOKEN[%lu] = %s\n", out->token_len, token_buf);

    } else if (out->method == MSG_Q_GP) {
        char ih_buf[21];
        strncat(ih_buf, (const char*)out->ih, 21);
        printf("\t\tMSG_Q_GP -> IH = %s\n", ih_buf);

    } else if (out->method == MSG_Q_FN) {
        char target_buf[21];
        strncat(target_buf, (const char*)out->target, 21);
        printf("\t\tMSG_Q_FN -> TARGET = %s\n", target_buf);

    } else if (out->method == MSG_R_FN) {
        printf("\t\t MSG_R_FN -> NODES[%lu] = ...\n", out->n_nodes);

    } else if (out->method == MSG_R_GP) {
        if (out->n_nodes > 0)
            printf("\t\tMSG_R_GP -> NODES[%lu] = ...\n", out->n_nodes);
        if (out->n_peers > 0)
            printf("\t\tMSG_R_GP -> PEERS[%lu] = ...\n", out->n_peers);

        char token_buf[BD_MAXLEN_TOKEN + 1];
        strncat(token_buf, (const char*)out->token, BD_MAXLEN_TOKEN + 1);
        printf("\t\tMSG_R_GP -> TOKEN[%lu] = %s\n", out->token_len, token_buf);
    }
}
