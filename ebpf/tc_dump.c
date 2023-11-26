#include "tc_dump.h"
#include "bpf_tc.h"

char __license[] SEC("license") = "GPL";

static __always_inline void
handle_skb(struct __sk_buff *skb, dir_t dir) {
  event_t ev = {};

  if (!filter_tc(skb))
    return;

  ev.direction = dir;
  set_output_tc(skb, &ev);

  bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
}

SEC("tc")
int on_egress(struct __sk_buff *skb) {
  handle_skb(skb, DIR_EGRESS);

  return TC_ACT_OK;
}

SEC("tc")
int on_ingress(struct __sk_buff *skb) {
  handle_skb(skb, DIR_INGRESS);

  return TC_ACT_OK;
}