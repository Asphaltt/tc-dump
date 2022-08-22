# tc-dump

`tc-dump` is a network packet information dumping tool like tcpdump. It's based
on [tc-bpf](https://man7.org/linux/man-pages/man8/tc-bpf.8.html).

It uses tc-filter ingress to dump incoming packets, uses tc-filter egress to
dump outcoming packets.

## Usage

```bash
# ./tc-dump -h
Usage of ./tc-dump:
      --clear-tc-qdisc            clear tc-qdisc when exit
  -d, --device strings            network devices to run tc-dump
  -A, --filter-addr string        filter source or destination address with lower priority of --filter-saddr and --filter-daddr
  -D, --filter-daddr string       filter destination address
      --filter-dport uint16       filter destination port of TCP/UDP
  -M, --filter-mark uint32        filter mark
  -P, --filter-port uint16        filter source or destination port of TCP/UDP
      --filter-proto string       filter l4 protocol, only TCP/UDP/ICMP
  -S, --filter-saddr string       filter source address
      --filter-sport uint16       filter source port of TCP/UDP
  -V, --filter-vlan-id uint16     filter VLAN ID
  -X, --filter-vxlan-vni uint32   filter VxLAN VNI
pflag: help requested
```

An output example:

```bash
ifindex: 2(enp1s0) dir=egress mark=0x0(0)
        ETH: 56:00:03:e1:40:a6 -> fe:00:03:e1:40:a6, protocol IPv4
        IPv4: 149.28.xx.yy -> 118.200.xxx.yy, header length 20, dscp 0x10, total length 144, id 0x93f6, TTL 64, protocol TCP
        TCP: 22 -> 57680, seq 1116972675, ack 64800706, flags PSH,ACK, win 165
ifindex: 2(enp1s0) dir=egress mark=0x0(0)
        ETH: 56:00:03:e1:40:a6 -> fe:00:03:e1:40:a6, protocol IPv4
        IPv4: 149.28.xx.yy -> 118.200.xxx.yy, header length 20, dscp 0x10, total length 88, id 0x93f7, TTL 64, protocol TCP
        TCP: 22 -> 57680, seq 1116972767, ack 64800706, flags PSH,ACK, win 165
ifindex: 2(enp1s0) dir=egress mark=0x0(0)
        ETH: 56:00:03:e1:40:a6 -> fe:00:03:e1:40:a6, protocol IPv4
        IPv4: 149.28.xx.yy -> 118.200.xxx.yy, header length 20, dscp 0x10, total length 128, id 0x93f8, TTL 64, protocol TCP
        TCP: 22 -> 57680, seq 1116972803, ack 64800706, flags PSH,ACK, win 165
ifindex: 2(enp1s0) dir=egress mark=0x0(0)
        ETH: 56:00:03:e1:40:a6 -> fe:00:03:e1:40:a6, protocol IPv4
        IPv4: 149.28.xx.yy -> 118.200.xxx.yy, header length 20, dscp 0x10, total length 344, id 0x93f9, TTL 64, protocol TCP
        TCP: 22 -> 57680, seq 1116972879, ack 64800706, flags PSH,ACK, win 165
ifindex: 2(enp1s0) dir=egress mark=0x0(0)
        ETH: 56:00:03:e1:40:a6 -> fe:00:03:e1:40:a6, protocol IPv4
        IPv4: 149.28.xx.yy -> 118.200.xxx.yy, header length 20, dscp 0x10, total length 384, id 0x93fa, TTL 64, protocol TCP
        TCP: 22 -> 57680, seq 1116973171, ack 64800706, flags PSH,ACK, win 165
```

## Requirements

`tc-dump` requires >= 5.2 kernel to run.
