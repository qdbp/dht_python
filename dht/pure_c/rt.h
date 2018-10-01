#ifndef DHT_RT_H
#define DHT_RT_H

#include <netinet/ip.h>
#include <stdbool.h>
#include "bdecode.h"
#include "dht.h"

#define RT_TOTAL_CONTACTS (256 * 256 * 256)

typedef enum RT_STATUS {
    RT_REP_SUCCESS,
    RT_REP_NO_EVICT,
    RT_REP_INVALID_NODE,
} rt_status_t;

#define RT_MAX_Q 7  // check quality bitwidth in rt_nodeinfo_t

typedef struct rt_nodeinfo_t {
    _Alignas(32) char nid[20];
    // network byte order
    u32 in_addr;
    // network byte order
    u16 sin_port;
    u8 quality : 3;
} rt_nodeinfo_t;

#define AS_SOCKADDR_IN(node_ptr)                                 \
    {                                                            \
        .sin_family = AF_INET, .sin_port = (node_ptr)->sin_port, \
        .sin_addr.s_addr = (node_ptr)->in_addr                   \
    }

#define PNODE_AS_SOCKADDR_IN(pnode_ptr)                      \
    {                                                        \
        .sin_family = AF_INET,                               \
        .sin_port = *(u16*)((pnode_ptr) + NIH_LEN + IP_LEN), \
        .sin_addr.s_addr = *(u32*)((pnode_ptr) + NIH_LEN)    \
    }

void rt_init(void);

u16 byte_reverse_u16(u16);

bool validate_addr(u32, u16);
bool validate_nodeinfo(const rt_nodeinfo_t*);
bool is_nodeinfo_empty(const rt_nodeinfo_t*);
bool eq_nodeinfo_nid(const rt_nodeinfo_t*, const char*);

void write_nodeinfo(char*, const rt_nodeinfo_t*);

rt_status_t rt_random_replace_contact(const char*, u8);
rt_status_t rt_add_sender_as_contact(const parsed_msg*,
                                     const struct sockaddr_in*,
                                     u8);

rt_nodeinfo_t* rt_get_valid_neighbor_contact(const char*);
rt_nodeinfo_t* rt_get_cell(const char*);
rt_nodeinfo_t* rt_get_cell_by_coords(u8, u8, u8);

void rt_adj_quality(const char*, i64);
bool rt_check_evict(u8, u8);

#endif  // DHT_RT_H
