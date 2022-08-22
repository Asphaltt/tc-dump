#ifndef __TC_DUMP_H_
#define __TC_DUMP_H_

#include "vmlinux.h"

#include "bpf_endian.h"
#include "bpf_helpers.h"

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
} events SEC(".maps");

typedef struct config_t {
    __be16 vlan_id;
    __be32 vxlan_vni;

    u32 mark;

    __be32 saddr;
    __be32 daddr;
    __be32 addr;
    __be16 sport;
    __be16 dport;
    __be16 port;

    u8 l4_proto;
    u8 pad1[3];
} __attribute__((packed)) config_t;

static volatile const config_t __cfg = {};

#define __validate_skb(skb, hdr) (((u64)hdr + sizeof(*hdr)) <= skb->data_end)

static __always_inline bool
filter_meta(struct __sk_buff *skb, config_t *cfg)
{
    if (cfg->mark && cfg->mark != skb->mark)
        return true;

    return false;
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
filter_vlan(struct __sk_buff *skb, config_t *cfg)
{
    u8 vlan_present = skb->vlan_present;
    u16 vlan_id = skb->vlan_tci;
    vlan_id &= VLAN_ID_MASK;

    struct ethhdr *eth;
    struct vlan_hdr *vh;

#define validate_skb(hdr)          \
    if (!__validate_skb(skb, hdr)) \
    return true

    if (cfg->vlan_id && vlan_present && vlan_id != cfg->vlan_id)
        return true;

    eth = (typeof(eth))((u64)skb->data);
    validate_skb(eth);

    if (!is_vlan_proto(eth->h_proto))
        return !is_ipv4_proto(eth->h_proto);

    vh = (struct vlan_hdr *)(eth + 1);
    validate_skb(vh);

    if (cfg->vlan_id && (vh->h_vlan_TCI & VLAN_ID_MASK) == cfg->vlan_id)
        return true;

    return !is_ipv4_proto(vh->h_vlan_encapsulated_proto);
}

static __always_inline bool
filter_proto(struct iphdr *iph, config_t *cfg)
{
    switch (iph->protocol) {
    case IPPROTO_UDP:
    case IPPROTO_TCP:
    case IPPROTO_ICMP:
        return cfg->l4_proto && iph->protocol != cfg->l4_proto;

    default:
        return true;
    }
}

static __always_inline bool
is_vxlan_port(__be16 port)
{
    return port == bpf_htons(VXLAN_PORT);
}

static __always_inline bool
filter_l3_l4_vxlan(struct __sk_buff *skb,
    config_t *cfg)
{
    struct ethhdr *eth;
    struct iphdr *iph;
    struct udphdr *udph;
    struct vxlan_hdr *vxh;
    int l3_off, l4_off;

#define validate_skb(hdr)          \
    if (!__validate_skb(skb, hdr)) \
    return true

    l3_off = calc_l3_off(skb);
    if (!l3_off)
        return true;

    iph = (typeof(iph))((u64)skb->data + l3_off);
    validate_skb(iph);

    if (iph->version != 4)
        return true;

    if (filter_proto(iph, cfg))
        return true;

    l4_off = l3_off + iph->ihl * 4;

    do {
        udph = (typeof(udph))((u64)skb->data + l4_off);
        validate_skb(udph);

        if (iph->protocol == IPPROTO_UDP && is_vxlan_port(udph->dest))
            break;

        // non-vxlan
        if (cfg->l4_proto && iph->protocol != cfg->l4_proto)
            return true;

        if (iph->protocol == IPPROTO_ICMP)
            return false;

        if (cfg->saddr && iph->saddr != cfg->saddr)
            return true;

        if (cfg->daddr && iph->daddr != cfg->daddr)
            return true;

        if (cfg->addr && (iph->saddr != cfg->addr && iph->daddr != cfg->addr))
            return true;

        if (cfg->sport && udph->source != cfg->sport)
            return true;

        if (cfg->dport && udph->dest != cfg->dport)
            return true;

        if (cfg->port && (udph->source != cfg->port && udph->dest != cfg->port))
            return true;

        return false;

    } while (0);

    // vxlan

    vxh = (struct vxlan_hdr *)((u64)skb->data + l4_off + sizeof(*udph));
    validate_skb(vxh);

    if (cfg->vxlan_vni && (vxh->vx_vni >> 8) != cfg->vxlan_vni)
        return true;

    eth = (typeof(eth))(vxh + 1);
    validate_skb(eth);

    if (!is_ipv4_proto(eth->h_proto))
        return true;

    iph = (typeof(iph))(eth + 1);
    validate_skb(iph);
    udph = (typeof(udph))(iph + 1);
    validate_skb(udph);

    if (iph->version != 4)
        return true;

    if (filter_proto(iph, cfg))
        return true;

    if (cfg->l4_proto && iph->protocol != cfg->l4_proto)
        return true;

    if (iph->protocol == IPPROTO_ICMP)
        return false;

    if (cfg->saddr && iph->saddr != cfg->saddr)
        return true;

    if (cfg->daddr && iph->daddr != cfg->daddr)
        return true;

    if (cfg->addr && (iph->saddr != cfg->addr && iph->daddr != cfg->addr))
        return true;

    if (cfg->sport && udph->source != cfg->sport)
        return true;

    if (cfg->dport && udph->dest != cfg->dport)
        return true;

    if (cfg->port && (udph->source != cfg->port && udph->dest != cfg->port))
        return true;

    return false;
}

static __always_inline bool
filter(struct __sk_buff *skb)
{
    config_t cfg = __cfg;

    if (filter_meta(skb, &cfg))
        return true;

    if (filter_vlan(skb, &cfg))
        return true;

    if (filter_l3_l4_vxlan(skb, &cfg))
        return true;

    return false;
}

static __always_inline void
copy_headers(struct __sk_buff *skb, event_t *ev)
{
    struct ethhdr *eth;
    struct vlan_hdr *vh;
    struct iphdr *iph;
    struct udphdr *udph;
    struct tcphdr *tcph;
    struct vxlan_hdr *vxh;
    struct icmphdr *icmph;
    int var_off = 0, cpy_off = 0;

#define __memcpy(hdr)                                                     \
    do {                                                                  \
        if (bpf_skb_load_bytes_relative(skb, var_off, ev->data + cpy_off, \
                sizeof(*hdr), BPF_HDR_START_MAC)                          \
            != 0)                                                         \
            return;                                                       \
                                                                          \
        hdr = (typeof(hdr))(ev->data + cpy_off);                          \
        cpy_off += sizeof(*hdr);                                          \
        ev->total_len = cpy_off;                                          \
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
}

static __always_inline void
set_output(struct __sk_buff *skb, event_t *ev)
{
    ev->meta.ifindex = IFINDEX;
    ev->meta.mark = skb->mark;

    if (skb->vlan_present) {
        ev->vlan.h_vlan_encapsulated_proto = 1; // indicate tci existing
        ev->vlan.h_vlan_TCI = skb->vlan_tci;
    }

    copy_headers(skb, ev);
}

#endif