#ifndef DHT_CTL_H
#define DHT_CTL_H

#include "bdecode.h"
#include "dht.h"
#include "rt.h"

void ctl_handle_peers(parsed_msg*);
void ctl_handle_nodes(parsed_msg*);
void ctl_handle_ihash(parsed_msg*);

bool ctl_decide_ping(const char* pnode);

#endif
