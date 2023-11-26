# tc-dump

`tc-dump` is a network packet information dumping tool like tcpdump. It's based
on [tc-bpf](https://man7.org/linux/man-pages/man8/tc-bpf.8.html).

It uses tc-filter ingress to dump incoming packets, uses tc-filter egress to
dump outcoming packets.

## Usage

```bash
# ./tc-dump -h
Usage: ./tc-dump [options] [pcap-filter]
    Available pcap-filter: see "man 7 pcap-filter"
    Available options:
  -d, --device strings       network devices to run tc-dump
  -m, --filter-mark uint32   filter mark for tc-dump
  -k, --keep-tc-qdisc        keep tc-qdisc when exit
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

## Build

With latest `libpcap` installed, build `tc-dump` with:

```bash
go generate
CGO_ENABLED=1 go build
# ignore cgo warnings
```

Install latest `libpcap` on Ubuntu:

```bash
# Get latest libpcap from https://www.tcpdump.org/
wget https://www.tcpdump.org/release/libpcap-1.10.4.tar.gz
cd libpcap-1.10.4
./configure --disable-rdma --disable-shared --disable-usb --disable-netmap --disable-bluetooth --disable-dbus --without-libnl
make
sudo make install
```

## Recommended reference

1. [Tcpdump advanced filters](https://blog.wains.be/2007/2007-10-01-tcpdump-advanced-filters/)
