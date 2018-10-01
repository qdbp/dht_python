#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <uv.h>
#include "bdecode.h"
#include "dht.h"
#include "log.h"
#include "msg.h"
#include "rt.h"

#define CHECK(r, msg)                                     \
    if (r < 0) {                                          \
        fprintf(stderr, "%s: %s\n", msg, uv_strerror(r)); \
        exit(1);                                          \
    }

#define DEFAULT_QUAL 1

static char g_recv_buf[BD_MAXLEN] = {0};

static uv_loop_t* main_loop;
static uv_udp_t g_udp_server;
static uv_timer_t g_statgather_timer;
static uv_timer_t g_bootstrap_timer;

static const rt_nodeinfo_t g_bootstrap_node = {
    .nid =
        {
            '2',  0xf5, 'N',  'i',  's',  'Q',  0xff, 'J', 0xec, ')',
            0xcd, 0xba, 0xab, 0xf2, 0xfb, 0xe3, 'F',  '|', 0xc2, 'g',
        },
    .in_addr = 183949123,
    // the "reverse" of 6881
    .sin_port = 57626,
};

static void handle_msg(parsed_msg*, const struct sockaddr_in*);

static void recv_msg_cb(uv_udp_t* handle,
                        ssize_t nread,
                        const uv_buf_t* rcvbuf,
                        const struct sockaddr* saddr,
                        unsigned flags) {
    if (saddr == NULL) {
        return;
    }

    // This is separate from the case above logically, but for now we do
    // nothing.
    if (nread == 0) {
        return;
    }

    parsed_msg rcvd;
    stat_t bd_status = krpc_bdecode(rcvbuf->base, nread, &rcvd);

    if (bd_status != ST_bd_a_no_error) {
        st_inc(bd_status);
        return;
    }

    st_inc(ST_rx_tot);
    handle_msg(&rcvd, (const struct sockaddr_in*)saddr);
}

static inline void send_msg(char* msg,
                            u64 len,
                            const struct sockaddr_in* dest,
                            stat_t acct) {
    uv_buf_t send_bufs[1] = {{
        .base = msg,
        .len = len,
    }};

#if LOGLEVEL < 5
    char ipaddr[18];
    uv_ip4_name(dest, ipaddr, 18);
    DEBUG("message of length %lu", len)
    DEBUG("sending to: %s:%d", ipaddr, byte_reverse_u16(dest->sin_port))
#endif

    int status =
        uv_udp_try_send(&g_udp_server, send_bufs, 1, (struct sockaddr*)dest);

    if (status >= 0) {
        st_inc(acct);
        st_inc(ST_tx_tot);
    } else {
        DEBUG("send status: %s", uv_strerror(status))
        st_inc(ST_tx_msg_drop_overflow);
    }
}

inline static void send_to_node(char* msg,
                                u64 len,
                                const rt_nodeinfo_t* dest_node,
                                stat_t acct) {
    const struct sockaddr_in dest = AS_SOCKADDR_IN(dest_node);
    send_msg(msg, len, &dest, acct);
}

inline static void send_to_pnode(char* msg, u64 len, char* pnode, stat_t acct) {
    const struct sockaddr_in dest = PNODE_AS_SOCKADDR_IN(pnode);
    send_msg(msg, len, &dest, acct);
}

void ping_sweep_nodes(parsed_msg* krpc_msg) {
    char ping[MSG_BUF_LEN];
    u64 len;

    for (int ix = 0; ix < krpc_msg->n_nodes; ix++) {
        len = msg_q_pg(ping, (krpc_msg->nodes) + (NODEINFO_LEN * ix));
        send_to_pnode(ping, len, (krpc_msg->nodes) + (NODEINFO_LEN * ix),
                      ST_tx_q_pg);
    }
}

static void handle_msg(parsed_msg* krpc_msg, const struct sockaddr_in* saddr) {
    char reply[MSG_BUF_LEN] = {0};
    u64 len = 0;
    rt_nodeinfo_t* pnode;

    switch (krpc_msg->method) {
        case MSG_Q_PG:
            rt_add_sender_as_contact(krpc_msg, saddr, 1);
            len = msg_r_pg(reply, krpc_msg);
            send_msg(reply, len, saddr, ST_rx_q_gp);
            break;

        case MSG_Q_FN:
            rt_add_sender_as_contact(krpc_msg, saddr, 2);

            pnode = rt_get_valid_neighbor_contact(krpc_msg->nid);
            if (pnode != NULL) {
                len = msg_r_fn(reply, krpc_msg, pnode);
                send_msg(reply, len, saddr, ST_tx_r_fn);
            }
            break;

        case MSG_Q_GP:
            st_inc(ST_rx_q_gp);
            rt_add_sender_as_contact(krpc_msg, saddr, 1);

            // TODO handle ihashes
            INFO("got infohahsh %08lx%08lx%04x", *(u64*)(krpc_msg->ih),
                 *(u64*)(krpc_msg->ih + 8), *(u32*)(krpc_msg->ih + 16))

            pnode = rt_get_valid_neighbor_contact(krpc_msg->nid);
            if (pnode != NULL) {
                len = msg_r_fn(reply, krpc_msg, pnode);
                send_msg(reply, len, saddr, ST_tx_q_pg);
            }
            break;

        case MSG_R_FN:
            st_inc(ST_rx_r_fn);
            if (krpc_msg->n_nodes == 0) {
                ERROR("Empty 'nodes' in R_FN")
                st_inc(ST_err_bd_empty_r_gp);
                break;
            }

            ping_sweep_nodes(krpc_msg);
            break;

        case MSG_R_GP:
            st_inc(ST_rx_r_gp);

            if (krpc_msg->n_peers > 0) {
                st_inc(ST_rx_r_gp_values);
                // TODO handle peer
            }
            if (krpc_msg->n_nodes > 0) {
                st_inc(ST_rx_r_gp_nodes);
                // TODO handle gp nodes
            }

            ping_sweep_nodes(krpc_msg);
            break;

        case MSG_R_PG:
            st_inc(ST_rx_r_pg);
            rt_add_sender_as_contact(krpc_msg, saddr, 1);
            break;

        default:
            ERROR("Unhandled krpc method name %s (%d)",
                  get_method_name(krpc_msg->method), krpc_msg->method)
            st_inc(ST_err_bd_handle_fallthrough);
            break;
    }
}

static inline void on_alloc(uv_handle_t* client,
                            size_t suggested_size,
                            uv_buf_t* buf) {
    buf->base = g_recv_buf;
    buf->len = BD_MAXLEN;
}

void init_subsystems(void) {
    INFO("Initializing rt...")
    rt_init();
    INFO("Initializing bd...")
    bd_init();
    INFO("Initializing st...")
    st_init();
    INFO("... done init.")
}

void loop_statgather_cb(uv_timer_t* timer) {
    static int statgather_ctr;
    // INFO("statgather %d", statgather_ctr);
}

void loop_bootstrap_cb(uv_timer_t* timer) {
    char msg[MSG_BUF_LEN];

    char random_target[NIH_LEN];
    getrandom(random_target, NIH_LEN, 0);

    u64 len = msg_q_fn(msg, &g_bootstrap_node, random_target);

    send_to_node(msg, len, &g_bootstrap_node, ST_tx_q_fn);

    // uv_buf_t send_bufs[1] = {{
    //     .base = msg,
    //     .len = len,
    // }};

    // DEBUG("msg = %s", msg);
    // DEBUG("len = %lu", len);

    // const struct sockaddr_in dest = AS_SOCKADDR_IN(node);
    // uv_udp_try_send(&g_udp_server, send_bufs, 1, (struct sockaddr *)&dest);
    // send_msg(msg, len, &dest, ST_tx_q_fn);

    INFO("Bootstrapped.")
}

int main(int argc, char* argv[]) {
    init_subsystems();

    int status;
    struct sockaddr_in addr;

    main_loop = uv_default_loop();

    // INITIALIZE UDP SERVER
    status = uv_udp_init(main_loop, &g_udp_server);
    CHECK(status, "init");

    uv_ip4_addr("192.168.0.10", 6881, &addr);

    status = uv_udp_bind(&g_udp_server, (const struct sockaddr*)&addr, 0);
    CHECK(status, "bind");

    status = uv_udp_recv_start(&g_udp_server, on_alloc, recv_msg_cb);
    CHECK(status, "recv");

    // INIT statgather
    status = uv_timer_init(main_loop, &g_statgather_timer);
    CHECK(status, "statgather timer init");
    status =
        uv_timer_start(&g_statgather_timer, &loop_statgather_cb, 1000, 1000);
    CHECK(status, "statgather start")

    // INIT BOOTSTRAP
    status = uv_timer_init(main_loop, &g_bootstrap_timer);
    CHECK(status, "statgather timer init");
    status = uv_timer_start(&g_bootstrap_timer, &loop_bootstrap_cb, 1000, 5000);
    CHECK(status, "statgather start")

    // RUN LOOP
    uv_run(main_loop, UV_RUN_DEFAULT);

    return 0;
}
