package main

import (
	"bytes"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

type directionType uint16

func (d directionType) String() string {
	switch d {
	case 1:
		return DirIngress
	case 2:
		return DirEgress
	default:
		return "UNKNOWN"
	}
}

type event struct {
	VlanTCI        uint16
	VlanEncapProto uint16

	Ifindex uint32
	Mark    uint32

	Direction directionType

	TotalLen uint16
	Data     [108]byte
}

const _ = int(unsafe.Sizeof(event{}))

func (ev *event) output(devs map[int]string) {
	var b bytes.Buffer
	b.Grow(int(ev.TotalLen))

	fmt.Fprintf(&b, "ifindex: %d(%s) ", ev.Ifindex, devs[int(ev.Ifindex)])
	fmt.Fprintf(&b, "dir=%s ", ev.Direction)
	fmt.Fprintf(&b, "mark=0x%x(%d)\n", ev.Mark, ev.Mark)

	if ev.VlanEncapProto != 0 {
		fmt.Fprintf(&b, "\tVLAN: ID=%d\n", ev.VlanTCI&0x0FFF)
	}

	ev.outputHeaders(&b, ev.Data[:ev.TotalLen])

	fmt.Print(b.String())
}

func (ev *event) outputHeaders(b *bytes.Buffer, buf []byte) {
	eth, buf := newEthhdr(buf)
	fmt.Fprintf(b, "\tETH: %s\n", eth)

	isVlan, isIP := eth.isVlanProto(), eth.isIPProto()
	for isVlan {
		var vh vlanhdr
		vh, buf = newVlanhdr(buf)
		fmt.Fprintf(b, "\tVLAN: %s\n", vh)
		buf = buf[len(vh):]

		isVlan, isIP = vh.isVlanProto(), vh.isIPProto()
	}

	if !isIP {
		fmt.Fprint(b, "\tNext protocol should be IPv4\n")
		return
	}

	iph, buf := newIPhdr(buf)
	if !iph.isV4() {
		fmt.Fprint(b, "\tOnly support IPv4\n")
		return
	}
	fmt.Fprintf(b, "\tIPv4: %s\n", iph)

	switch iph.protocol() {
	case unix.IPPROTO_ICMP:
		icmph, _ := newIcmphdr(buf)
		fmt.Fprintf(b, "\tICMPv4: %s\n", icmph)

	case unix.IPPROTO_TCP:
		tcph, _ := newTCPhdr(buf)
		fmt.Fprintf(b, "\tTCP: %s\n", tcph)

	case unix.IPPROTO_UDP:
		udph, buf := newUDPhdr(buf)
		fmt.Fprintf(b, "\tUDP: %s\n", udph)

		if !udph.isVxLAN() {
			return
		}

		vxh, buf := newVxlanhdr(buf)
		fmt.Fprintf(b, "\tVxLAN: %s\n", vxh)

		ev.outputHeaders(b, buf)
	}
}
