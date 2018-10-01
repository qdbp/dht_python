#ifndef STAT_C

#define FORSTAT(X) \
    X(_ST_ENUM_START) \
/* received message statistics */ \
    X(rx_tot) \
    X(rx_oserr) \
    X(rx_err_received) \
    X(rx_q_ap) \
    X(rx_q_fn) \
    X(rx_q_pg) \
    X(rx_q_gp) \
    X(rx_r_ap) \
    X(rx_r_fn) \
    X(rx_r_gp) \
    X(rx_r_pg) \
    X(rx_r_gp_nodes) \
    X(rx_r_gp_values) \
/* transmitted message statistics */\
    X(tx_tot) \
    X(tx_exc) \
    X(tx_msg_drop_overflow) \
    X(tx_q_ap) \
    X(tx_q_fn) \
    X(tx_q_pg) \
    X(tx_q_gp) \
    X(tx_r_ap) \
    X(tx_r_fn) \
    X(tx_r_gp) \
    X(tx_r_pg) \
/* bad messages that pass bdecode but that we reject */ \
    X(bm_ap_bad_name) \
    X(bm_ap_bad_token) \
    X(bm_nodes_invalid) \
    X(bm_peers_bad) \
    X(bm_bullshit_dkad) \
    X(bm_evil_source) \
/* routing table constant */\
    X(rt_replace_accept) \
    X(rt_replace_reject) \
    X(rt_replace_invalid) \
    X(rt_newnode_ping) \
    X(rt_newnode_drop_luck) \
    X(rt_newnode_drop_dup) \
    X(rt_newnode_invalid) \
    X(rt_miss) \
/* database interaction statistics */\
    X(db_update_peers) \
    X(db_rows_inserted) \
/* infohash lookup cycle statistics... mind these well */\
    X(ih_nodes_unmatched) \
    X(ih_nodes_matched) \
    X(ih_peers_unmatched) \
    X(ih_peers_matched) \
    X(ih_naked_exhausted) \
    X(ih_move_naked_dup_nid) \
    X(ih_move_naked_dup_ih) \
    X(ih_move_naked_to_hold) \
    X(ih_move_rx_to_staging) \
    X(ih_move_hold_to_staging) \
    X(ih_move_staging_to_naked) \
    X(ih_unhold_db) \
    X(ih_stage_n_raw) \
    X(ih_stage_n_prefiltered) \
    X(ih_stage_n_recycled) \
    X(ih_stage_n_lookup) \
    X(ih_db_lookup_success) \
/* A: the message is accepted */\
    X(bd_a_no_error) \
/* X: the bdecoding is ill-formed or we can't handle the message at all */\
    X(bd_x_msg_too_long) \
    X(bd_x_bad_eom) \
    X(bd_x_bad_char) \
    X(bd_x_list_is_key) \
/* Y: the message violates KRPC norms */ \
    X(bd_y_bad_length_peer) \
    X(bd_y_bad_length_nodes) \
    X(bd_y_bad_length_ih) \
    X(bd_y_bad_length_nid) \
    X(bd_y_bad_length_target) \
    X(bd_y_inconsistent_type) \
    X(bd_y_no_nid) \
    X(bd_y_no_tok) \
    X(bd_y_port_overflow) \
    X(bd_y_ap_no_port) \
    X(bd_y_apgp_no_ih) \
    X(bd_y_empty_gp_response) \
    X(bd_y_fn_no_target) \
    X(bd_y_naked_value) \
    X(bd_y_vals_wo_token) \
/* Z: the message is likely valid, but is suspicious or uninteresting to us */\
    X(bd_z_tok_too_long) \
    X(bd_z_token_too_long) \
    X(bd_z_unknown_query) \
    X(bd_z_unknown_type) \
    X(bd_z_incongruous_message) \
    X(bd_z_dicts_too_deep) \
    X(bd_z_ping_body) \
    X(bd_z_error_type) \
/* E: there is a programming error */\
    X(err_bd_handle_fallthrough) \
    X(err_bd_empty_r_gp) \
    X(err_rt_no_contacts) \
    X(err_rt_pulled_bad_node) \
    X(err_rx_exc) \
\
    X(_ST_ENUM_END)

#include <string.h>

#define AS_ENUM(x) x,
#define AS_STR(x) #x,
#define AS_STRLEN(x) (strlen(#x) - 1),


char *ST_names[] = {
    FORSTAT(AS_STR)
};

const unsigned long ST_strlen[] = {
    FORSTAT(AS_STRLEN)
};

typedef enum ST {
    FORSTAT(AS_ENUM)
} ST;

#define STAT_C
#endif
