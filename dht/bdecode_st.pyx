# cython: profile=True
# cython: boundscheck=False
# cython: wraparound=False

include "dht_h.pxi"

from libc.string cimport memcmp, memset

cimport cython
from dht.bdecode_st cimport parsed_msg

DEF BD_IKEY_VALUES = 1
DEF BD_IKEY_NODES = 1 << 1
DEF BD_IKEY_TOKEN = 1 << 2
DEF BD_IKEY_IH = 1 << 3
DEF BD_IKEY_NID = 1 << 4
DEF BD_IKEY_TARGET = 1 << 5
DEF BD_IKEY_IMPLPORT = 1 << 6
DEF BD_IKEY_PORT = 1 << 7
DEF BD_IKEY_AP_NAME = 1 << 8
DEF BD_OKEY_A = 1 << 9
DEF BD_OKEY_T = 1 << 10
DEF BD_OKEY_Q = 1 << 11
DEF BD_OKEY_R = 1 << 12
DEF BD_OKEY_Y = 1 << 13

DEF BD_IKEY_ANY_BODY =\
    BD_IKEY_NODES | BD_IKEY_VALUES | BD_IKEY_IH | BD_IKEY_TARGET | BD_IKEY_TOKEN

DEF BD_IKEY_ANY_NON_TOKEN_BODY =\
    BD_IKEY_NODES | BD_IKEY_VALUES | BD_IKEY_IH | BD_IKEY_TARGET

DEF R_ANY =            MSG_R_FN | MSG_R_GP | MSG_R_PG
DEF Q_ANY = MSG_Q_AP | MSG_Q_FN | MSG_Q_GP | MSG_Q_PG

cdef:
    # FIXME: autogenerate from enum?
    dict krpc_method_names = {
        MSG_Q_AP: 'MSG_Q_AP',
        MSG_Q_FN: 'MSG_Q_FN',
        MSG_Q_GP: 'MSG_Q_GP',
        MSG_Q_PG: 'MSG_Q_PG',
        MSG_R_FN: 'MSG_R_FN',
        MSG_R_GP: 'MSG_R_GP',
        MSG_R_PG: 'MSG_R_PG',
    }

cdef:
    struct bd_state:
        u64 fail
        u64 dict_depth
        u64 list_depth
        bint at_end
        bint reading_dict_key
        # set when we find a key, expecting a particular value
        # set during the reading_dict_key phase
        u64 current_key
        u64 seen_keys
        # u64 legal_kinds
        u64 msg_kind
        bint save_ap_port
        bint is_response
        # set at the start, then subtracted from once a given key is found
        # updated during the reading_dict_key phase

    u8 *bdk_NID = b'id'
    u64 bdk_NID_slen = 2
    u8 *bdk_PORT = b'port'
    u64 bdk_PORT_slen = 4
    u8 *bdk_NODES = b'nodes'
    u64 bdk_NODES_slen = 5
    u8 *bdk_TOKEN = b'token'
    u64 bdk_TOKEN_slen = 5
    u8 *bdk_TARGET = b'target'
    u64 bdk_TARGET_slen = 6
    u8 *bdk_VALUES = b'values'
    u64 bdk_VALUES_slen = 6
    u8 *bdk_IH = b'info_hash'
    u64 bdk_IH_slen = 9
    u8 *bdk_IP = b'implied_port'
    u64 bdk_IP_slen = 12
    u8 *bdk_AP_NAME = b'name'
    u64 bdk_AP_NAME_slen = 4

    u8 *bdv_AP = b'announce_peer'
    u64 bdv_AP_slen = 13
    u8 *bdv_GP = b'get_peers'
    u64 bdv_GP_slen = 9
    u8 *bdv_FN = b'find_node'
    u64 bdv_FN_slen = 9
    u8 *bdv_PG = b'ping'
    u64 bdv_PG_slen = 4

    IF BD_TRACE:
        list g_trace = []

@cython.profile(False)
cdef inline i64 krpc_bdecode_atoi(u8 * buf, u64 *ix, u64 maxlen, bd_state *state):
    '''
    Decode strictly nonnegative, colon-terminated decimal integers. Fast.

    Is stateful: xdvances the buffer index in-place. Advances the index
    an extra position on returning, thus consuming the termination symbol.
    '''

    cdef i64 out = 0
    cdef i64 sign = 1

    if ix[0] < maxlen and buf[ix[0]] == 45:
        sign = -1
        ix[0] += 1

    # ord(decimal_digit) = decimal_digit + 48
    while ix[0] < maxlen and 48 <= buf[ix[0]] < 58:
        out = 10 * out + buf[ix[0]] - 48
        ix[0] += 1

    # consume the position of the b':' or b'e'
    ix[0] += 1

    # the previous tests failed because of overflow iff ix[0] = maxlen + 1 here
    # therefore this test passes iff not overflow
    if ix[0] > maxlen:
        state.fail = ST.bd_x_msg_too_long

    return out * sign

@cython.profile(False)
cdef void krpc_bdecode_i(
        u8 * data,
        u64 *ix,
        u64 maxlen,
        bd_state *state,
        parsed_msg *out):

    # NOTE there are currently no integer keys of values we are interested in
    # therefore, we simply consume any integers with no interaction

    cdef i64 result

    ix[0] += 1
    result = krpc_bdecode_atoi(data, ix, maxlen, state)

    if state.save_ap_port:
        IF BD_TRACE: g_trace.append('int: saving port')
        if result < (1 << 16):
            out.ap_port = <u16> result
        # NOTE if we get a corrupted port, bail out and scrap the whole message
        # as unreliable
        else:
            IF BD_TRACE: g_trace.append('int: port overflow FAIL')
            state.fail = ST.bd_y_port_overflow

@cython.profile(False)
cdef inline void krpc_bdecode_s(
        u8 * data,
        u64 *ix,
        u64 maxlen,
        bd_state *state,
        parsed_msg *out):
    '''
    The most important krpc_bdecode function, since this is the only one that
    actuall extracts useful data (which is all strings).

    The state setup by other functions was for the benefit of krpc_bdecode_s.

    This is a lovable monstrosity. Be delicate with it. If you don't know what
    something does, think 7 times before changing it, or you will feel pain.
    '''
    cdef:
        i64 slen, start

    slen = krpc_bdecode_atoi(data, ix, maxlen, state)
    # if overflow, unwind instantly
    if state.fail != ST.bd_a_no_error:
        return

    start = ix[0]

    # if reading the string would overflow, set the fail flag and unwind
    if maxlen < start + slen:
        state.fail = ST.bd_x_msg_too_long
        IF BD_TRACE: g_trace.append(f'FAIL: {state.fail}')
        return

    ix[0] += slen

    IF BD_TRACE:
        g_trace.append(
            'parsing string, rk is ' + str(state.reading_dict_key) +
            ', string is ' + str(data[start:start + slen]) +
            ', dict depth is ' + str(state.dict_depth) +
            ', list depth is ' + str(state.list_depth)
        )

    if state.reading_dict_key:
        IF BD_TRACE: g_trace.append(f'reading key')
        # reset some flags on a new key
        state.save_ap_port = 0
        state.current_key = 0

        if state.dict_depth == 0:
            state.fail = ST.bd_y_naked_value
            IF BD_TRACE: g_trace.append(f'fail {state.fail}')

        elif state.dict_depth == 1:
            IF BD_TRACE: g_trace.append(f'depth 1')
            # all outer keys have length 1, can check it off the bat
            if slen == 1:
                # "string comparison" of a single bytes is just integer comparison
                # if we get a response key, we don't set a current key
                # but we no longer expect a q key or r key
                if data[start] == 97:  # b'a'
                    if state.seen_keys & BD_OKEY_R:
                        state.fail = ST.bd_y_inconsistent_type
                        return
                    # state.legal_kinds &= Q_ANY
                    IF BD_TRACE: g_trace.append('>>> matched okey "a"')
                    state.msg_kind &= Q_ANY
                    state.current_key = BD_OKEY_A
                    state.seen_keys |= BD_OKEY_A

                # similarly, if we get an r key, we no longer expect a, or q
                elif data[start] == 114: # b'r'
                    if state.seen_keys & (BD_OKEY_A | BD_OKEY_Q):
                        state.fail = ST.bd_y_inconsistent_type
                        return
                    IF BD_TRACE: g_trace.append('>>> matched okey "r"')
                    state.msg_kind &= R_ANY
                    state.current_key = BD_OKEY_R
                    state.seen_keys |= BD_OKEY_R

                # if we get a t key, we set the current key to tok
                elif data[start] == 116:  # b't':
                    IF BD_TRACE: g_trace.append('>>> matched okey "t"')
                    state.current_key = BD_OKEY_T
                    state.seen_keys |= BD_OKEY_T

                elif data[start] == 113:  # b'q':
                    if state.seen_keys & BD_OKEY_R:
                        state.fail = ST.bd_y_inconsistent_type
                        return
                    IF BD_TRACE: g_trace.append('>>> matched okey "q"')
                    state.msg_kind &= Q_ANY
                    state.current_key = BD_OKEY_Q
                    state.seen_keys |= BD_OKEY_Q

                elif data[start] == 121:  # b'y'
                    IF BD_TRACE: g_trace.append('>>> matched okey "y"')
                    state.seen_keys |= BD_OKEY_Y
                    state.current_key = BD_OKEY_Y
                else:
                    pass
        # READ KEYS DEPTH 2
        elif state.dict_depth == 2:
            IF BD_TRACE: g_trace.append(f'depth 2')
            # XXX you could put this in a for loop to DRY it up... but this
            # is kind of fixed for all eternity, and expanded form might be
            # faster
            if slen == bdk_NID_slen and\
                    0 == memcmp(data + start, bdk_NID, slen):

                IF BD_TRACE: g_trace.append('>>> matched ikey ID; * -> *')
                state.current_key = BD_IKEY_NID
                state.seen_keys |= BD_IKEY_NID

            elif slen == bdk_IH_slen and\
                    0 == memcmp(data + start, bdk_IH, slen):

                IF BD_TRACE: g_trace.append(
                    '>>> matched ikey INFO_HASH; * -> MSG_Q_AP|MSG_Q_GP')
                state.msg_kind &= (MSG_Q_GP | MSG_Q_AP)
                state.current_key = BD_IKEY_IH
                state.seen_keys |= BD_IKEY_IH

            elif slen == bdk_NODES_slen and\
                    0 == memcmp(data + start, bdk_NODES, slen):

                IF BD_TRACE: g_trace.append(
                    '>>> matched ikey NODES; * -> MSG_R_FN|MSG_R_GP')
                state.msg_kind &= (MSG_R_FN | MSG_R_GP)
                state.current_key = BD_IKEY_NODES
                state.seen_keys |= BD_IKEY_NODES

            elif slen == bdk_VALUES_slen and\
                    0 == memcmp(data + start, bdk_VALUES, slen):

                IF BD_TRACE: g_trace.append(
                    '>>> matched ikey VALUES; * -> MSG_R_GP')
                state.msg_kind &= MSG_R_GP
                state.current_key = BD_IKEY_VALUES
                state.seen_keys |= BD_IKEY_VALUES

            elif slen == bdk_TOKEN_slen and\
                    0 == memcmp(data + start, bdk_TOKEN, slen):

                IF BD_TRACE: g_trace.append(
                    '>>> matched ikey TOKEN; X -> X & ~MSG_R_FN'
                )
                state.msg_kind &= (~MSG_Q_FN)
                # NOTE many random queries include a token, we allow for it
                # state.msg_kind &= (MSG_Q_AP | MSG_R_GP | MSG_Q_GP)
                state.current_key = BD_IKEY_TOKEN
                state.seen_keys |= BD_IKEY_TOKEN

            elif slen == bdk_TARGET_slen and\
                    0 == memcmp(data + start, bdk_TARGET, slen):

                IF BD_TRACE: g_trace.append(
                    '>>> matched ikey TARGET; * -> MSG_Q_FN')
                state.msg_kind &= MSG_Q_FN
                state.current_key = BD_IKEY_TARGET
                state.seen_keys |= BD_IKEY_TARGET

            elif slen == bdk_PORT_slen and\
                    0 == memcmp(data + start, bdk_PORT, slen):

                # we do not restrict the legal kinds, since other
                # messages can have a port as extra data we ignore
                IF BD_TRACE: g_trace.append('>>> matched ikey PORT')
                state.seen_keys |= BD_IKEY_PORT
                state.save_ap_port = 1

            elif slen == bdk_IP_slen and\
                    0 == memcmp(data + start, bdk_IP, slen):

                IF BD_TRACE: g_trace.append(
                    '>>> matched ikey IMPLIED_PORT; * -> MSG_Q_AP'
                )
                state.msg_kind &= MSG_Q_AP
                state.current_key = BD_IKEY_IMPLPORT
                state.seen_keys |= BD_IKEY_IMPLPORT

            # ignore name field in non-announce peer messages
            elif slen == bdk_AP_NAME_slen and\
                    state.msg_kind & MSG_Q_AP and\
                    0 == memcmp(data + start, bdk_AP_NAME, slen):

                IF BD_TRACE: g_trace.append(
                    '>>> matched ikey NAME; ~MSG_Q_AP -> MSG_Q_AP')
                state.msg_kind = MSG_Q_AP
                state.current_key = BD_IKEY_AP_NAME
                state.seen_keys |= BD_IKEY_AP_NAME
            else:
                pass
        # no KRPC dicts should have a depth more than 2:
        # fail instantly if we see this
        else:
            # XXX :^)
            state.fail = ST.bd_z_dicts_too_deep
            IF BD_TRACE: g_trace.append(f'FAIL {state.fail}')
            return

    # READ VALUES
    else:
        if state.dict_depth == 1:
            IF BD_TRACE: g_trace.append(f'READ VALUES DEPTH 1')
            # set the query type, if one is found...
            if state.current_key == BD_OKEY_Q:
                if slen == bdv_AP_slen and\
                        0 == memcmp(data + start, bdv_AP, slen):

                    state.msg_kind &= MSG_Q_AP
                    IF BD_TRACE: g_trace.append(f'!!! q is MSG_Q_AP')

                elif slen == bdv_FN_slen and\
                        0 == memcmp(data + start, bdv_FN, slen):

                    state.msg_kind &= MSG_Q_FN
                    IF BD_TRACE: g_trace.append(f'!!! q is MSG_Q_FN')

                elif slen == bdv_GP_slen and\
                        0 == memcmp(data + start, bdv_GP, slen):

                    state.msg_kind &= MSG_Q_GP
                    IF BD_TRACE: g_trace.append(f'!!! q is MSG_Q_GP')

                elif slen == bdv_PG_slen and\
                        0 == memcmp(data + start, bdv_PG, slen):

                    state.msg_kind &= MSG_Q_PG
                    IF BD_TRACE: g_trace.append(f'!!! q is MSG_Q_PG')
                # ... reject martian queries
                else:
                    state.fail = ST.bd_z_unknown_query
                    IF BD_TRACE: g_trace.append(f'FAIL {state.fail}')
            # set the token...
            elif state.current_key == BD_OKEY_T:
                # if it's short enough
                if slen > BD_MAXLEN_TOK:
                    state.fail = ST.bd_z_tok_too_long
                    IF BD_TRACE: g_trace.append(f'bad tok, fail {state.fail}')
                else:
                    IF BD_TRACE: g_trace.append(
                        f'!!! TOK[{slen}] = {data[start:ix[0]]}'
                    )
                    out.tok_len = slen
                    memcpy(out.tok, data + start, slen)

            elif state.current_key == BD_OKEY_Y:
                if slen == 1:
                    if data[start] == 101:  # ord('e')
                        state.fail = ST.bd_z_error_type
                        IF BD_TRACE: g_trace.append(f'FAIL {state.fail}')
                    elif data[start] == 114:  # ord('r')
                        state.msg_kind &= R_ANY
                    elif data[start] == 113:  # ord('q')
                        state.msg_kind &= Q_ANY
                    else:
                        state.fail = ST.bd_z_unknown_type
                        return
                else:
                    state.fail = ST.bd_z_unknown_type
                    return
            else:
                pass

        elif state.dict_depth == 2:
            IF BD_TRACE: g_trace.append(f'READ VALUES DEPTH 2')
            # within a list, we expect only value strings
            if state.current_key == BD_IKEY_VALUES:
                if state.list_depth == 1:
                    # we are in a values list, but we read a weird string
                    # NOTE we assume the entire message is corrupted and bail out,
                    # parsing very conservatively is the key to sanity
                    if slen != PEERINFO_LEN:
                        IF BD_TRACE: g_trace.append(f'fail {state.fail}')
                        state.fail = ST.bd_y_bad_length_peer
                        return
                    if out.n_peers < BD_MAX_PEERS:
                        memcpy(
                            out.peers + (PEERINFO_LEN * out.n_peers),
                            data + start,
                            PEERINFO_LEN,
                        )
                        out.n_peers += 1
                        IF BD_TRACE: g_trace.append(f'!!! {out.n_peers}th peer')

            elif state.current_key == BD_IKEY_NODES:
                # if the nodes array length is weird, or too long, fail
                if (slen == 0) or (slen % NODEINFO_LEN != 0):
                    state.fail = ST.bd_y_bad_length_nodes
                    IF BD_TRACE: g_trace.append(f'FAIL {state.fail}')
                    return

                if slen > (NODEINFO_LEN * BD_MAX_NODES):
                    IF BD_TRACE:
                        g_trace.append(
                            f'??? Truncating nodes {slen} to '
                            f'{NODEINFO_LEN * BD_MAX_NODES}'
                        )
                    slen = NODEINFO_LEN * BD_MAX_NODES

                IF BD_TRACE: g_trace.append(f'!!! NODES[{slen//26}] = ...')
                out.n_nodes = slen // NODEINFO_LEN
                memcpy(out.nodes, data + start, slen)

            elif state.current_key == BD_IKEY_TOKEN:
                if slen > BD_MAXLEN_TOKEN:
                    state.fail = ST.bd_z_token_too_long
                    IF BD_TRACE: g_trace.append(f'FAIL {state.fail}')
                    return
                else:
                    memcpy(out.token, data + start, slen)
                    IF BD_TRACE: g_trace.append(f'!!! TOKEN[{slen}] = ...')
                    out.token_len = slen

            elif state.current_key == BD_IKEY_TARGET:
                if slen != NIH_LEN:
                    state.fail = ST.bd_y_bad_length_target
                    IF BD_TRACE: g_trace.append(f'FAIL {state.fail}')
                    return
                else:
                    IF BD_TRACE: g_trace.append(f'!!! TARGET[{slen}] = ...')
                    memcpy(out.target, data + start, slen)

            elif state.current_key == BD_IKEY_NID:
                if slen != NIH_LEN:
                    state.fail = ST.bd_y_bad_length_nid
                    IF BD_TRACE: g_trace.append(f'FAIL {state.fail}')
                    return
                else:
                    memcpy(out.nid, data + start, slen)
                    IF BD_TRACE: g_trace.append('!!! NID')

            elif state.current_key == BD_IKEY_IH:
                if slen != NIH_LEN:
                    state.fail = ST.bd_y_bad_length_ih
                    IF BD_TRACE: g_trace.append(f'FAIL {state.fail}')
                    return
                else:
                    memcpy(out.ih, data + start, slen)
                    IF BD_TRACE: g_trace.append('!!! IH')

            elif state.current_key == BD_IKEY_AP_NAME:
                if slen > BD_MAXLEN_AP_NAME:
                    IF BD_TRACE: g_trace('??? AP_NAME too long, ignoring.')
                else:
                    IF BD_TRACE: g_trace.append(
                        f'!!! AP_NAME[{slen}] = {data[start:start + slen]}'
                    )
                    memcpy(out.ap_name, data + start, slen)
                    out.ap_name_len = slen
            else:
                pass
        # READ VALUES TOO DEEP
        else:
            state.fail = ST.bd_z_dicts_too_deep
            IF BD_TRACE: g_trace.append(f'FAIL {state.fail}')
            return

    # else fall through with success, ignoring the key/value

@cython.profile(False)
cdef void krpc_bdecode_l(
        u8 * data,
        u64 *ix,
        u64 maxlen,
        bd_state *state,
        parsed_msg *pmsg):

    # lists cannot be keys, fail instantly
    if state.reading_dict_key:
        state.fail = ST.bd_x_list_is_key
        return

    ix[0] += 1

    state.list_depth += 1
    while True:
        krpc_bdecode_dispatch(data, ix, maxlen, state, pmsg)
        # on fail, unwind the stack and gtfo
        if state.fail != ST.bd_a_no_error:
            IF BD_TRACE: g_trace.append(f'list: unwinding fail {state.fail}')
            return
        # if we read the end, reset the end flag and the in-list marker
        if state.at_end:
            IF BD_TRACE: g_trace.append(f'list: got end')
            state.at_end = 0
            state.list_depth -= 1
            return

@cython.profile(False)
cdef void krpc_bdecode_d(
        u8 * data,
        u64 *ix,
        u64 maxlen,
        bd_state *state,
        parsed_msg *out):

    ix[0] += 1
    state.dict_depth += 1

    while True:
        # read the key, as a key
        state.reading_dict_key = 1
        krpc_bdecode_dispatch(data, ix, maxlen, state, out)
        if state.fail != ST.bd_a_no_error:
            IF BD_TRACE: g_trace.append(f'dict: unwiding key fail {state.fail}')
            return
        # if instead of a key we read the end, we unwind a level of
        # dict, and reset the end flag
        if state.at_end:
            IF BD_TRACE: g_trace.append(f'dict: got end')
            state.at_end = 0
            state.dict_depth -= 1
            return
        # read the value
        state.reading_dict_key = 0
        krpc_bdecode_dispatch(data, ix, maxlen, state, out)
        # it is an error to read end as a key
        if state.fail != ST.bd_a_no_error:
            IF BD_TRACE: g_trace.append(f'dict: unwiding value fail {state.fail}')
            return
        if state.at_end:
            state.fail = ST.bd_x_bad_eom
            IF BD_TRACE: g_trace.append(f'dict: unexpected end fail {state.fail}')
            return

@cython.profile(False)
cdef inline void krpc_bdecode_fail(
        u8 *data, u64 *ix, u64 maxlen, bd_state *state, parsed_msg *out):

    state.fail = ST.bd_x_bad_char
    return

@cython.profile(False)
cdef inline void krpc_bdecode_e(
        u8 *data, u64 *ix, u64 maxlen, bd_state *state, parsed_msg *out):
    state.at_end = 1
    ix[0] += 1
    return

cdef:
    void (*g_krpc_dispatch_table[256])(u8*, u64*, u64, bd_state*, parsed_msg*)
    cdef i64 ix

for ix in range(0x100):
    g_krpc_dispatch_table[ix] = krpc_bdecode_fail

for ix in range(0x30, 0x40):
    g_krpc_dispatch_table[ix] = krpc_bdecode_s

g_krpc_dispatch_table[ord('d')] = krpc_bdecode_d
g_krpc_dispatch_table[ord('e')] = krpc_bdecode_e
g_krpc_dispatch_table[ord('i')] = krpc_bdecode_i
g_krpc_dispatch_table[ord('l')] = krpc_bdecode_l
g_krpc_dispatch_table[ord('s')] = krpc_bdecode_s

@cython.profile(False)
cdef inline void krpc_bdecode_dispatch(
        u8 * data,
        u64 *ix,
        u64 maxlen,
        bd_state *state,
        parsed_msg *out):

    if ix[0] < maxlen:
        g_krpc_dispatch_table[data[ix[0]]](data, ix, maxlen, state, out)
    else:
        IF BD_TRACE: g_trace.append('dispatch: overflow ix, failing')
        state.fail = ST.bd_x_msg_too_long

cdef u64 krpc_bdecode(bytes data, parsed_msg *out):
    '''
    Efficiently decodes a KRPC message, looking for pre-existing fields,
    into a fixed parsed_msg structure.

    Returns 1 if the parse was successful, 0 otherwise.

    If 0 is returned, the output structure should NOT BE USED IN ANY WAY,
    since it is not guaranteed to be consistent, or even wholly initialized,
    in the case of a parse failure.
    '''
    cdef u64 chunk_offset = 0
    cdef u64 ld = len(data)
    cdef u8 buf[BD_MAXLEN]
    cdef bd_state state

    if ld > BD_MAXLEN:
        state.fail = ST.bd_x_msg_too_long
        return state.fail

    IF BD_TRACE: g_trace.clear()

    out.n_nodes = out.n_peers = 0
    out.tok_len = out.token_len = out.ap_name_len = 0

    memcpy_bytes(buf, data, ld)

    state.fail = ST.bd_a_no_error
    state.dict_depth = 0
    state.list_depth = 0
    state.at_end = 0

    state.current_key = 0
    state.seen_keys = 0
    state.msg_kind = 0xffffffff
    state.save_ap_port = 0
    state.is_response = True

    krpc_bdecode_dispatch(buf, &chunk_offset, ld, &state, out)

    if state.fail != ST.bd_a_no_error:
        return state.fail

    # MESSAGE SANITY FILTERING
    # ALL messages need a NID
    if not state.seen_keys & BD_IKEY_NID:
        return ST.bd_y_no_nid

    # ...and a TOK
    if not state.seen_keys & BD_OKEY_T:
        return ST.bd_y_no_tok

    IF BD_TRACE: g_trace.append(
        f'??? DECIDING keys {state.seen_keys:b} methods {state.msg_kind:b}',
    )

    # METHOD RESOLUTION
    # exact APs and GPs need an info_hash only
    if state.msg_kind & Q_ANY:
        IF BD_TRACE: g_trace.append('??? DECIDING as query')
        if state.msg_kind == MSG_Q_AP or state.msg_kind == MSG_Q_GP:
            if not state.seen_keys & BD_IKEY_IH:
                IF BD_TRACE: g_trace.append(
                    '=== REJECT (q_gp | q_ap) && ~ih'
                )
                return ST.bd_y_apgp_no_ih

            elif state.msg_kind == MSG_Q_AP and not\
                    state.seen_keys & (BD_IKEY_PORT | BD_IKEY_IMPLPORT):
                IF BD_TRACE: g_trace.append(
                    '=== REJECT q_ap && ~(port | impl_port)'
                )
                return ST.bd_y_ap_no_port
            else:
                out.method = state.msg_kind
                IF BD_TRACE: g_trace.append(
                    f'=== ACCEPT {krpc_method_names[state.msg_kind]}')

        # fns need a target
        elif state.msg_kind == MSG_Q_FN:
            if not state.seen_keys & BD_IKEY_TARGET:
                IF BD_TRACE: g_trace.append('=== REJECT q_fn && ~target')
                return ST.bd_y_fn_no_target
            else:
                IF BD_TRACE: g_trace.append('=== ACCEPT MSG_Q_FN')
                out.method = MSG_Q_FN

        # accept only simple pings
        elif state.msg_kind == MSG_Q_PG:
            if state.seen_keys & BD_IKEY_ANY_BODY:
                IF BD_TRACE: g_trace.append('=== REJECT q_pg && body')
                return ST.bd_z_ping_body
            else:
                IF BD_TRACE: g_trace.append('=== ACCEPT MSG_Q_PG')
                out.method = MSG_Q_PG

        else:
            IF BD_TRACE: g_trace.append('=== REJECT fallthrough q_any')
            return ST.bd_z_unknown_query

    elif state.msg_kind & R_ANY:
        IF BD_TRACE: g_trace.append('??? DECIDING as reply')

        # TOKEN and (VALUES or NODES) <-> R_GP
        if state.seen_keys & BD_IKEY_TOKEN and\
                state.seen_keys & (BD_IKEY_VALUES | BD_IKEY_NODES):
            IF BD_TRACE: g_trace.append(
                '??? '
            )
            out.method = MSG_R_GP
            if out.n_nodes + out.n_peers == 0:
                IF BD_TRACE: g_trace.append(
                    '=== REJECT r_gp && (n + v) == 0'
                )
                return ST.bd_y_empty_gp_response

            IF BD_TRACE: g_trace.append(
                '=== ACCEPT token && (nodes | values) -> MSG_R_GP'
            )

        # VALUES and ~TOKEN <-> bad R_GP
        elif state.seen_keys & BD_IKEY_VALUES and\
                not state.seen_keys & BD_IKEY_TOKEN:
            IF BD_TRACE: g_trace.append(
                '=== REJECT values && ~token'
            )
            return ST.bd_y_vals_wo_token

        # ~TOKEN and ~VALUES and NODES <-> R_FN
        elif state.seen_keys & BD_IKEY_NODES:
            IF BD_TRACE: g_trace.append(
                '=== ACCEPT ~token && ~values && nodes -> MSG_R_FN'
            )
            out.method = MSG_R_FN

        # ~NODES and ~VALUES <-> R_PG
        else:
            if state.seen_keys & BD_IKEY_ANY_NON_TOKEN_BODY:
                IF BD_TRACE: g_trace.append(
                    '=== REJECT (body - tok) && ~(nodes || values) -> bad r_pg'
                )
                return ST.bd_z_ping_body

            IF BD_TRACE: g_trace.append(
                    '=== ACCEPT ~(values | nodes) -> MSG_R_PG')
            out.method = MSG_R_PG

    else:
        IF BD_TRACE:
            g_trace.append('=== REJECT ~[type & (q | r)] -> incongruous')
        return ST.bd_z_incongruous_message
    
    return ST.bd_a_no_error

cdef void print_parsed_msg(parsed_msg *out):

    print(f'\tMETH = {krpc_method_names[out.method]}')
    print(f'\tTOK[{out.tok_len}] = "{out.tok[0:out.tok_len]}"')
    print(f'\tNID[20] = "{out.nid[0:20]}"')

    if out.method == MSG_Q_AP:
        print(f'\t\tMSG_Q_AP -> IH = "{out.ih[0:20]}"')
        print(f'\t\tMSG_Q_AP -> PORT = {out.ap_port} (IP = {out.ap_implied_port})')
        print(f'\t\tMSG_Q_AP -> TOKEN[{out.token_len} = "{out.token[0:out.token_len]}"')

    if out.method == MSG_Q_GP:
        print(f'\t\tMSG_Q_GP -> IH = "{out.ih[0:20]}"')

    if out.method == MSG_Q_FN:
        print(f'\t\tMSG_Q_FN -> TARGET = "{out.target[0:20]}"')

    if out.method == MSG_R_FN:
        print(f'\t\t MSG_R_FN -> NODES[{out.n_nodes}] = ...')

    if out.method == MSG_R_GP:
        if out.n_nodes > 0:
            print(f'\t\tMSG_R_GP -> NODES[{out.n_nodes}] = ...')
        if out.n_peers > 0:
            print(f'\t\tMSG_R_GP -> PEERS[{out.n_peers}] = ...')
        print(f'\t\tMSG_R_GP -> TOKEN[{out.token_len} = "{out.token[0:out.token_len]}"')

@cython.profile(False)
cdef inline void memcpy_bytes(u8 *target, u8 *source, u64 up_to):
    memcpy(target, source, up_to)
