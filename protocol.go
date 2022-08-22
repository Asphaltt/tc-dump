package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/sys/unix"
)

var be = binary.BigEndian

type ethhdr []byte

func newEthhdr(b []byte) (ethhdr, []byte) {
	return b[:14], b[14:]
}

func (h ethhdr) proto() uint16 {
	proto := be.Uint16(h[12:14])
	return proto
}

func (h ethhdr) isVlanProto() bool {
	proto := h.proto()
	return proto == unix.ETH_P_8021Q || proto == unix.ETH_P_8021AD
}

func (h ethhdr) isIPProto() bool {
	proto := h.proto()
	return proto == unix.ETH_P_IP
}

func (h ethhdr) String() string {
	dst := net.HardwareAddr(h[:6])
	src := net.HardwareAddr(h[6:12])
	proto := h.proto()

	var nxtProto string
	switch proto {
	case unix.ETH_P_IP:
		nxtProto = "IPv4"
	case unix.ETH_P_IPV6:
		nxtProto = "IPv6"
	case unix.ETH_P_8021Q, unix.ETH_P_8021AD:
		nxtProto = "VLAN"
	case unix.ETH_P_ARP:
		nxtProto = "ARP"
	default:
		nxtProto = "~UNK~"
	}

	return fmt.Sprintf("%s -> %s, protocol %s", src, dst, nxtProto)
}

type vlanhdr []byte

func newVlanhdr(b []byte) (vlanhdr, []byte) {
	return b[:4], b[4:]
}

func (h vlanhdr) isVlanProto() bool {
	proto := be.Uint16(h[2:4])
	return proto == unix.ETH_P_8021Q || proto == unix.ETH_P_8021AD
}

func (h vlanhdr) isIPProto() bool {
	proto := be.Uint16(h[2:4])
	return proto == unix.ETH_P_IP
}

func (h vlanhdr) String() string {
	vlanID := be.Uint16(h[:2])
	vlanID &= 0x0FFF

	return fmt.Sprintf("ID %d", vlanID)
}

type iphdr []byte

func newIPhdr(b []byte) (iphdr, []byte) {
	return b[:20], b[20:]
}

func (h iphdr) isV4() bool {
	b := h[0]
	b >>= 4
	return b == 4
}

func (h iphdr) protocol() uint8 {
	return h[9]
}

func (h iphdr) String() string {
	ihl := (h[0] & 0x0F) * 4
	dscp := h[1] & (0xFF ^ 0b11)
	totLen := be.Uint16(h[2:4])
	id := be.Uint16(h[4:6])
	ttl := h[8]
	protocol := h[9]
	src, _ := netip.AddrFromSlice(h[12:16])
	dst, _ := netip.AddrFromSlice(h[16:20])

	var nxtProto string
	switch protocol {
	case unix.IPPROTO_ICMP:
		nxtProto = "ICMPv4"
	case unix.IPPROTO_UDP:
		nxtProto = "UDP"
	case unix.IPPROTO_TCP:
		nxtProto = "TCP"
	default:
		nxtProto = "~UNK~"
	}

	return fmt.Sprintf("%s -> %s, header length %d, dscp 0x%02x, total length %d, id 0x%04x, TTL %d, protocol %s",
		src, dst, ihl, dscp, totLen, id, ttl, nxtProto)
}

type udphdr []byte

func newUDPhdr(b []byte) (udphdr, []byte) {
	return b[:8], b[8:]
}

func (h udphdr) isVxLAN() bool {
	port := be.Uint16(h[2:4])
	return port == 4789
}

func (h udphdr) String() string {
	src := be.Uint16(h[:2])
	dst := be.Uint16(h[2:4])

	return fmt.Sprintf("%d -> %d", src, dst)
}

type vxlanhdr []byte

func newVxlanhdr(b []byte) (vxlanhdr, []byte) {
	return b[:8], b[8:]
}

func (h vxlanhdr) String() string {
	vni := be.Uint32(h[4:8])
	vni >>= 8

	return fmt.Sprintf("VNI %d", vni)
}

type tcphdr []byte

func newTCPhdr(b []byte) (tcphdr, []byte) {
	return b[:20], b[20:]
}

func (h tcphdr) String() string {
	src, dst := be.Uint16(h[:2]), be.Uint16(h[2:4])
	seq, ack := be.Uint32(h[4:8]), be.Uint32(h[8:12])
	tcpFlags := h[13]
	winSize := be.Uint16(h[14:16])

	var f []string
	flagsName := []string{
		"FIN",
		"SYN",
		"RST",
		"PSH",
		"ACK",
		"URG",
		"ECE",
		"CWR",
	}
	for i := range flagsName {
		if tcpFlags&(1<<uint8(i)) != 0 {
			f = append(f, flagsName[i])
		}
	}
	if h[12]&0b1 != 0 {
		f = append(f, "NS")
	}
	flags := strings.Join(f, ",")

	return fmt.Sprintf("%d -> %d, seq %d, ack %d, flags %s, win %d",
		src, dst, seq, ack, flags, winSize)
}

type icmphdr []byte

func newIcmphdr(b []byte) (icmphdr, []byte) {
	return b[:8], b[8:]
}

func (h icmphdr) String() string {
	typ, code := h[0], h[1]

	if typ == 0 {
		return fmt.Sprintf("Echo Reply, code %d", code)
	} else if typ == 8 {
		return fmt.Sprintf("Echo Request, code %d", code)
	} else {
		return fmt.Sprintf("type %d, code %d", typ, code)
	}
}
