#ifndef DHT_MSG_H
#define DHT_MSG_H

#include "bdecode.h"
#include "dht.h"
#include "rt.h"

#define MSG_BUF_LEN 512

void write_sid(char*, const char*);

u64 msg_q_gp(char*, const rt_nodeinfo_t* dest, const char*);
u64 msg_q_fn(char*, const rt_nodeinfo_t* dest, const char*);
u64 msg_q_pg(char*, char*);
u64 msg_r_fn(char*, const parsed_msg*, const rt_nodeinfo_t*);
u64 msg_r_gp(char*, const parsed_msg*, const rt_nodeinfo_t*);
u64 msg_r_pg(char*, const parsed_msg*);

#endif  // DHT_MSG_H
