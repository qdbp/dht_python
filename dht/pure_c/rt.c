#include <errno.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "log.h"
#include "rt.h"
#include "stat.h"
#include "util.h"

static rt_nodeinfo_t* g_rt = NULL;

static bool g_dkad_offsets[256] = {0};
static const char _zeros[NIH_LEN] = {0};

inline u16 byte_reverse_u16(u16 x) {
    return 256 * (x % 256) + x / 256;
}

inline void unpack_nodeinfo(rt_nodeinfo_t* dst, const char* src) {
    /*
     * Unpack a 26-byte DHT nodeinfo string into an rt_nodeinfo_t structure.
     */
    memcpy(dst->nid, src, NIH_LEN);
    memcpy(&(dst->in_addr), src + NIH_LEN, IP_LEN);
    memcpy(&(dst->sin_port), src + NIH_LEN + IP_LEN, PORT_LEN);
}

inline void pack_nodeinfo(char* dst, const rt_nodeinfo_t* src) {
    memcpy(dst, src->nid, NIH_LEN);
    memcpy(dst + NIH_LEN, &(src->in_addr), IP_LEN);
    memcpy(dst + NIH_LEN + IP_LEN, &(src->sin_port), PORT_LEN);
}

inline bool is_nodeinfo_empty(const rt_nodeinfo_t* nodeinfo) {
    return 0 != memcmp(nodeinfo->nid, _zeros, NIH_LEN);
}

inline bool eq_nodeinfo_nid(const rt_nodeinfo_t* node1, const char* other_nid) {
    return (0 == memcmp(node1->nid, other_nid, NIH_LEN));
}

inline bool validate_addr(u32 in_addr, u16 sin_port) {
    unsigned char* addr_bytes = (unsigned char*)&in_addr;
    unsigned char a = addr_bytes[0];
    unsigned char b = addr_bytes[1];
    unsigned char c = addr_bytes[2];
    unsigned char d = addr_bytes[3];

    int rport;
    if ((rport = byte_reverse_u16(sin_port)) <= 1024) {
        DEBUG("invalid port %d", rport);
        return false;
    }

    if (((a & 0xf0) == 240) || (a == 0) || (a == 10) || (a == 127) ||
        (a == 100 && (b & 0xc0) == 64) || (a == 172 && (b & 0xf0) == 16) ||
        (a == 198 && (b & 0xfe) == 18) || (a == 169 && b == 254) ||
        (a == 192 && b == 168) || (a == 192 && b == 0 && c == 0) ||
        (a == 192 && b == 0 && c == 2) || (a == 192 && b == 31 && c == 196) ||
        (a == 192 && b == 51 && c == 100) ||
        (a == 192 && b == 52 && c == 193) ||
        (a == 192 && b == 175 && c == 48) ||
        (a == 198 && b == 51 && c == 100) || (a == 203 && b == 0 && c == 113) ||
        (a == 255 && b == 255 && c == 255 && d == 255)) {
        DEBUG("Invalid IP %d.%d.%d.%d", a, b, c, d);
        return false;
    }

    return true;
}

inline bool validate_nodeinfo(const rt_nodeinfo_t* nodeinfo) {
    return (!is_nodeinfo_empty(nodeinfo)) &&
           validate_addr(nodeinfo->in_addr, nodeinfo->sin_port);
}

static inline void write_peerinfo(char* target, u32 in_addr, u16 sin_port) {
    // the address and port are stored in network byte order in sockaddr_in
    // so the following is safe
    char* addr_bytes = (char*)&(in_addr);
    char* port_bytes = (char*)&(sin_port);
    for (int ix = 0; ix < 4; ix += 1) {
        target[ix] = addr_bytes[ix];
    }

    target[4] = port_bytes[0];
    target[5] = port_bytes[1];
}

void write_nodeinfo(char* dst, const rt_nodeinfo_t* node) {
    // relies on contiguous memory layout
    memcpy(dst, node, NIH_LEN + IP_LEN + PORT_LEN);
    // write_peerinfo(dst + NIH_LEN, node->in_addr, node->sin_port);
}

void dump_rt() {
    // TODO should add option to dump this piecemeal
    FILE* f = fopen(RT_FN, "w");
    fwrite(g_rt, sizeof(rt_nodeinfo_t), RT_TOTAL_CONTACTS, f);
    fclose(f);
}

void load_rt() {
    int fd = open(RT_FN, O_RDWR);
    if (fd == -1) {
        ERROR("Could not open rt file, bailing.");
        exit(-1);
    }

    struct stat info = {0};
    if (0 != fstat(fd, &info)) {
        ERROR("Could not stat rt file, bailing.")
        exit(-1);
    }

    u64 want_size = RT_TOTAL_CONTACTS * sizeof(rt_nodeinfo_t);

    if (info.st_size != want_size) {
        ERROR("Bad size (%ld) rt file found.", info.st_size);
        ERROR("If upgrading to a new rt format, you must migrate it manually")
        exit(-1);
    }

    void* addr =
        mmap(NULL, want_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (addr == (void*)-1) {
        ERROR("Failed to mmap rt file: %s.", strerror(errno));
        exit(-1);
    }
    g_rt = (rt_nodeinfo_t*)addr;
}

inline rt_nodeinfo_t* rt_get_cell(const char* nid) {
    /*
    Returns the index in the routing table corresponding to the given
    nid. Obviously not injective.

    ASSUMES 8 CONTACTS AT DEPTH 3
    */
    u8 a, b, c;
    a = nid[0];
    b = nid[1];
    c = nid[2];

    return rt_get_cell_by_coords(a, b, c);
}

inline rt_nodeinfo_t* rt_get_cell_by_coords(u8 a, u8 b, u8 c) {
    return g_rt + ((u32)a << 16) + ((u32)b << 8) + c;
}

rt_status_t rt_add_sender_as_contact(const parsed_msg* krpc,
                                     const struct sockaddr_in* addr,
                                     u8 base_qual) {
    char sender_pnode[NODEINFO_LEN];
    u64 rep_status;

    memcpy(sender_pnode, krpc->nid, NIH_LEN);

    if (!validate_addr(addr->sin_addr.s_addr, addr->sin_port)) {
        st_inc(ST_rt_replace_invalid);
        return RT_REP_INVALID_NODE;
    }

    write_peerinfo(sender_pnode + NIH_LEN, addr->sin_addr.s_addr,
                   addr->sin_port);
    rep_status = rt_random_replace_contact(sender_pnode, base_qual);

    switch (rep_status) {
        case RT_REP_SUCCESS:
            st_inc(ST_rt_replace_accept);
            break;
        case RT_REP_NO_EVICT:
            st_inc(ST_rt_replace_reject);
            break;
        default:
            st_inc(ST_rt_replace_invalid);
            break;
    }

    return rep_status;
}

rt_status_t rt_random_replace_contact(const char* new_pnode, u8 base_qual) {
    /*
    Possibly randomly replaces the contact for `new_pnode` in the routing
    table.

    The old contact has a chance to be evicted inversely related to
    its quality given by the quality table.

    If no contact is evicted, the new_contact is simply ignored.
    */

    rt_nodeinfo_t* node_spot = rt_get_cell(new_pnode);

    if (rt_check_evict(node_spot->quality, base_qual)) {
        // Assumes the relevant fields are contiguous in memory
        if (validate_nodeinfo((rt_nodeinfo_t*)new_pnode)) {
            memcpy(node_spot->nid, new_pnode, NIH_LEN);
            memcpy(&(node_spot->in_addr), new_pnode + NIH_LEN, IP_LEN);
            memcpy(&(node_spot->sin_port), new_pnode + NIH_LEN + IP_LEN,
                   PORT_LEN);
            node_spot->quality = base_qual <= RT_MAX_Q ? base_qual : RT_MAX_Q;
            return RT_REP_SUCCESS;
        } else {
            return RT_REP_INVALID_NODE;
        }
    } else {
        return RT_REP_NO_EVICT;
    }
}

bool rt_check_evict(u8 cur_qual, u8 cand_qual) {
    /*
    Checks if a node with quality `cur_qual` should be replaced with
    one of quality `cand_qual`.

    If `cand_qual` > `cur_qual`, evicts certainly. Else, evicts with
    probability 1 / 2 ** (cur_qual - cand_qual)
    */

    if (cand_qual >= cur_qual) {
        return true;
    }

    return randint(0, 1 << (cur_qual - cand_qual)) == 0;
}

void rt_adj_quality(const char* nid, i64 delta) {
    /*
    Adjusts the quality of the routing contact "nid", if it
    can be found. Otherwise, does nothing.
    */

    rt_nodeinfo_t* cur_nodeinfo = rt_get_cell(nid);

    // the contact we're trying to adjust has been replaced
    // just do nothing in this case
    if (!eq_nodeinfo_nid(cur_nodeinfo, nid)) {
        return;
    }

    u8 new_qual = cur_nodeinfo->quality + delta;
    cur_nodeinfo->quality = new_qual > RT_MAX_Q ? RT_MAX_Q : new_qual;
}

rt_nodeinfo_t* rt_get_valid_neighbor_contact(const char* target) {
    /*
    Returns a nid from the array of nids `narr` whose first two bytes
    match the target.
    */

    rt_nodeinfo_t* neighbor_cell = rt_get_cell(target);

    if (!is_nodeinfo_empty(neighbor_cell)) {
        return neighbor_cell;
    }

    rt_nodeinfo_t* alt_cell;

    // try one neighbor cell, then fail
    if (g_dkad_offsets[(int)target[2]] > 0) {
        alt_cell = neighbor_cell + 1;
    } else {
        alt_cell = neighbor_cell - 1;
    }

    if (!is_nodeinfo_empty(alt_cell)) {
        return alt_cell;
    } else {
        st_inc(ST_rt_miss);
        return NULL;
    }
}

void rt_nuke_node(char* target) {
    /*
    A node has been very naughty. It must be annihilated!
    */

    rt_nodeinfo_t* cell = rt_get_cell(target);
    // check the node hasn't been replaced in the interim
    if (0 == memcmp(cell, target, NIH_LEN)) {
        memset(cell, 0, sizeof(rt_nodeinfo_t));
    }
}

rt_nodeinfo_t* rt_get_random_valid_node() {
    /*
        Returns a random non-zero, valid node from the current routing table.

        Is much slower when the table is empty. Returns None if it can
        find no node at all.
        */

    u64 start_ix = randint(0, RT_TOTAL_CONTACTS);

    for (int ix = 0; ix < RT_TOTAL_CONTACTS; ix++) {
        u64 jx = (start_ix + ix) % RT_TOTAL_CONTACTS;
        u64 ax = jx >> 16;
        u64 bx = (jx >> 8) & 0xff;
        u64 cx = jx & 0xff;

        rt_nodeinfo_t* out = rt_get_cell_by_coords(ax, bx, cx);

        if (validate_nodeinfo(out)) {
            return out;
        }
        // clean up as we go
        else if (!is_nodeinfo_empty(out)) {
            memset(out, 0, sizeof(rt_nodeinfo_t));
        }
    }
    st_inc(ST_err_rt_no_contacts);
    ERROR("Could not find any random valid contact. RT in trouble!")
    return NULL;
}

void rt_init(void) {
    load_rt();
    g_dkad_offsets[0] = 1;
    g_dkad_offsets[255] = -1;
    for (int i = 1; i < 255; i += 1) {
        int xm = (i - 1) ^ i;
        int xp = (i + 1) ^ i;
        g_dkad_offsets[i] = xm < xp ? -1 : 1;
    }
}
