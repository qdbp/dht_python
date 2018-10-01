#include <time.h>
#include "dht.h"
#include "log.h"
#include "stat.h"

const char* stat_names[] = {FORSTAT(AS_STR)};

static u64 g_ctr[ST__ST_ENUM_END] = {0};
static u64 g_ctr_old[ST__ST_ENUM_END] = {0};
static u64 g_ctr_diff[ST__ST_ENUM_END] = {0};

static u64 time_old = 0;
static u64 time_now = 0;

void st_init() {
    time_now = (u64)time(0);
    time_old = (u64)time(0);
}

inline void st_inc(stat_t stat) {
    DEBUG("inc %s -> %lu", stat_names[stat], g_ctr[stat])
    g_ctr[stat] += 1;
}

inline void st_add(stat_t stat, u32 val) {
    g_ctr[stat] += val;
}

// not thread safe
void st_rollover(void) {
    for (int i = 0; i < ST__ST_ENUM_END; i++) {
        g_ctr_diff[i] = g_ctr[i] - g_ctr_old[i];
        g_ctr_old[i] = g_ctr[i];
    }
    time_old = time_now;
    time_now = (u64)time(0);
}
