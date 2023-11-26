#include "tc_dump.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "GPL";

static const volatile dir_t DIR = 0;

static __always_inline void
handle_skb(void *ctx, struct sk_buff *skb) {
  event_t ev = {};

  if (!filter_fentry(skb))
    return;

  ev.direction = DIR;
  set_output_fentry(skb, &ev);

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
}

SEC("fentry/tc")
int BPF_PROG(fentry_tc, struct sk_buff *skb) {
  handle_skb(ctx, skb);

  return BPF_OK;
}