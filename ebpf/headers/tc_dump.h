#ifndef __TC_DUMP_H_
#define __TC_DUMP_H_

#include "vmlinux.h"

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

#define VLAN_ID_MASK 0x0FFF

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/
#define ETH_P_8021Q 0x8100 /* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD 0x88A8 /* 802.1ad Service VLAN		*/

#define VXLAN_PORT 4789

static volatile const u32 IFINDEX = 0;

struct vxlan_hdr {
    __be32 vx_flags;
    __be32 vx_vni;
};

#define DIR_INGRESS 1
#define DIR_EGRESS 2

typedef struct meta_info {
    u32 ifindex;
    u32 mark;
} meta_info_t;

typedef u16 dir_t;

typedef struct event {
    struct vlan_hdr vlan;
    meta_info_t meta;

    dir_t direction;

    u16 total_len;
#define DATA_SIZE \
    (sizeof(struct ethhdr) + sizeof(struct vlan_hdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct vxlan_hdr) + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))
    u8 data[DATA_SIZE];
#undef DATA_SIZE
} __attribute__((packed)) event_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

typedef struct config_t {
    u32 mark;
} __attribute__((packed)) config_t;

static volatile const config_t __cfg = {};

#define __validate_skb(skb, hdr) (((u64)hdr + sizeof(*hdr)) <= skb->data_end)

static __always_inline bool
filter_meta(struct __sk_buff *skb, config_t *cfg)
{
    if (cfg->mark && cfg->mark != skb->mark)
        return false;

    return true;
}

static __noinline bool
filter_pcap_ebpf_l2(void *_skb, void *__skb, void *___skb, void *data, void* data_end)
{
    return data != data_end && _skb == __skb && __skb == ___skb;
}

static __always_inline bool
filter_pcap_l2(struct __sk_buff *skb)
{
    void *data = (void *)(long) skb->data;
    void *data_end = (void *)(long) skb->data_end;
    return filter_pcap_ebpf_l2((void *)skb, (void *)skb, (void *)skb, data, data_end);
}

static __always_inline bool
filter_pcap(struct __sk_buff *skb) {
    return filter_pcap_l2(skb);
}

static __always_inline bool
filter_tc(struct __sk_buff *skb)
{
    config_t cfg = __cfg;

    return filter_meta(skb, &cfg) && filter_pcap(skb);
}

static __always_inline bool
filter_fentry(struct sk_buff *skb)
{
    config_t cfg = __cfg;

    // filter meta
    if (cfg.mark && cfg.mark != BPF_CORE_READ(skb, mark))
        return false;

    // filter pcap
    void *skb_head = BPF_CORE_READ(skb, head);
    void *data = skb_head + BPF_CORE_READ(skb, mac_header);
    void *data_end = skb_head + BPF_CORE_READ(skb, tail);
    return filter_pcap_ebpf_l2((void *)skb, (void *)skb, (void *)skb, data, data_end);
}

static __always_inline bool
is_vlan_proto(__be16 proto)
{
    return proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD);
}

static __always_inline bool
is_ipv4_proto(__be16 proto)
{
    return proto == bpf_htons(ETH_P_IP);
}

static __always_inline int
calc_l3_off(struct __sk_buff *skb)
{
    struct ethhdr *eth;
    int l3_off = 0;

    eth = (typeof(eth))((u64)skb->data);
    if (!__validate_skb(skb, eth))
        return 0;

    l3_off += sizeof(*eth);
    if (is_vlan_proto(eth->h_proto))
        l3_off += sizeof(struct vlan_hdr);

    return l3_off;
}

static __always_inline bool
is_vxlan_port(__be16 port)
{
    return port == bpf_htons(VXLAN_PORT);
}

static __always_inline void
copy_headers(void *__skb, event_t *ev, bool is_tc)
{
    struct ethhdr *eth;
    struct vlan_hdr *vh;
    struct iphdr *iph;
    struct udphdr *udph;
    struct tcphdr *tcph;
    struct vxlan_hdr *vxh;
    struct icmphdr *icmph;
    int var_off = 0, cpy_off = 0;

#define __memcpy(hdr)                                                         \
    do {                                                                      \
        if (is_tc) {                                                          \
            struct __sk_buff *skb = (struct __sk_buff *)(u64)__skb;           \
            if (bpf_skb_load_bytes_relative(skb, var_off, ev->data + cpy_off, \
                    sizeof(*hdr), BPF_HDR_START_MAC) != 0)                    \
                return;                                                       \
                                                                              \
            hdr = (typeof(hdr))(ev->data + cpy_off);                          \
            cpy_off += sizeof(*hdr);                                          \
            ev->total_len = cpy_off;                                          \
        } else {                                                              \
            struct sk_buff *skb = (struct sk_buff *)(u64)__skb;               \
            void *skb_head = BPF_CORE_READ(skb, head);                        \
            void *data = skb_head + BPF_CORE_READ(skb, mac_header);           \
            if (bpf_probe_read_kernel(ev->data + cpy_off, sizeof(*hdr),       \
                data + var_off) != 0)                                         \
                return;                                                       \
                                                                              \
            hdr = (typeof(hdr))(ev->data + cpy_off);                          \
            cpy_off += sizeof(*hdr);                                          \
            ev->total_len = cpy_off;                                          \
        }                                                                     \
    } while (0)
#define memcpy_hdr(hdr) \
    __memcpy(hdr);      \
    var_off += sizeof(*hdr)
#define memcpy_ip_hdr(hdr) \
    __memcpy(hdr);         \
    var_off += (hdr->ihl * 4)

    memcpy_hdr(eth);

    if (is_vlan_proto(eth->h_proto)) {
        memcpy_hdr(vh);
        if (!is_ipv4_proto(vh->h_vlan_encapsulated_proto))
            return;
    } else if (!is_ipv4_proto(eth->h_proto)) {
        return;
    }

    memcpy_ip_hdr(iph);

    if (iph->protocol == IPPROTO_ICMP) {
        memcpy_hdr(icmph);
    } else if (iph->protocol == IPPROTO_TCP) {
        memcpy_hdr(tcph);
    } else if (iph->protocol == IPPROTO_UDP) {
        memcpy_hdr(udph);

        if (!is_vxlan_port(udph->dest))
            return;

        memcpy_hdr(vxh);

        memcpy_hdr(eth);

        memcpy_ip_hdr(iph);

        if (iph->protocol == IPPROTO_ICMP) {
            memcpy_hdr(icmph);
        } else if (iph->protocol == IPPROTO_TCP) {
            memcpy_hdr(tcph);
        } else if (iph->protocol == IPPROTO_UDP) {
            memcpy_hdr(udph);
        }
    }

#undef memcpy_ip_hdr
#undef memcpy_hdr
#undef __memcpy
}

static __always_inline void
set_output_tc(struct __sk_buff *skb, event_t *ev)
{
    ev->meta.ifindex = IFINDEX;
    ev->meta.mark = skb->mark;

    if (skb->vlan_present) {
        ev->vlan.h_vlan_encapsulated_proto = 1; // indicate tci existing
        ev->vlan.h_vlan_TCI = skb->vlan_tci;
    }

    copy_headers(skb, ev, true);
}

static __always_inline void
set_output_fentry(struct sk_buff *skb, event_t *ev)
{
    ev->meta.ifindex = IFINDEX;
    ev->meta.mark = BPF_CORE_READ(skb, mark);

    if (BPF_CORE_READ(skb, vlan_proto)) {
        ev->vlan.h_vlan_encapsulated_proto = 1; // indicate tci existing
        ev->vlan.h_vlan_TCI = BPF_CORE_READ(skb, vlan_tci);
    }

    copy_headers(skb, ev, false);
}

#endif