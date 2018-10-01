#ifndef DHT_DHT_H
#define DHT_DHT_H

#include <stdint.h>
#include <string.h>

#define u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t

#define i8 int8_t
#define i16 int16_t
#define i32 int32_t
#define i64 int64_t


// GENERIC IMMUTABLE
#define IP_MAX_LEN 18 // null - terminated

// KPRC #defineINITIONS
#define NIH_LEN 20
#define IP_LEN sizeof(u32)
#define PORT_LEN sizeof(u16)
#define PEERINFO_LEN (IP_LEN + PORT_LEN)
#define NODEINFO_LEN (NIH_LEN + PEERINFO_LEN)

// our key values
#define TOKEN 0x88
#define TOK 0x77


// SCRAPER CONSTANTS
// info loop
#define INFO_HEADER_EVERY 12
#define TERMINAL_WIDTH 190

// loop granularities
#define FP_SLEEP 0.05
#define GP_SLEEP 0.01
#define PURGE_SLEEP 0.1
#define HO_PURGE_SLEEP 5.0
#define BOOTSTRAP_SLEEP 1.0
#define CONTROL_SLEEP 1.0
#define INFO_SLEEP 5.0
#define SAVE_SLEEP 60.0
#define IH_STAGE_SLEEP 1.0
#define IH_DESC_SLEEP 5.0

// cache sizes and flush intervals
#define MAX_NODES 25000
#define IH_POOL_LEN 1 << 16
#define ROW_POOL_MAXLEN 1000
#define RECENT_PEER_CACHESIZE 1 << 20

#define RTT_BUF_LEN 1000
#define DKAD_BUF_LEN 1000
#define BULLSHIT_DKAD_THRESH 80

#define FP_THRESH MAX_NODES // 2
#define FP_NUMBER 5

#define BASE_IFL_TARGET 1000
#define IFL_TARGET_BACKOFF 0.95
#define IFL_TARGET_GROWTH 5
#define GPPS_RX_TARGET 10000
#define GPPS_RX_MAX 15000
#define BASE_IHASH_DISCARD 0.25
#define BASE_IHASH_REFRESH 0.03
#define BASE_IH_GP_HOLDOFF 60
#define BASE_IH_DB_HOLDOFF 600
#define BASE_PING_RATE 0.05
#define BASE_GP_TIMEOUT 1.0

#define DB_FN "./data/dht.db"
#define RT_FN "/home/main/programming/projects/dht/data/rt.dat"
#define RT_QUAL_FN "./data/rt_qual.dat"
#define INFO_FILE "./live_info.txt"

// rt constants
// #define RT_CONTACTS_PER_BIN 256

#define META_FLAG_VERIFIED 1

#endif // DHT_DHT_H
