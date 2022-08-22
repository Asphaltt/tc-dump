package main

import (
	"log"

	flag "github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
)

type flags struct {
	Devices []string

	FilterVlanID   uint16
	FilterVxlanVNI uint32

	FilterMark uint32

	FilterSaddr string
	FilterDaddr string
	FilterAddr  string
	FilterSport uint16
	FilterDport uint16
	FilterPort  uint16

	FilterProto string

	ClearTcQdisc bool
}

func parseFlags() *flags {
	var f flags

	flag.StringSliceVarP(&f.Devices, "device", "d", nil, "network devices to run tc-dump")

	flag.Uint16VarP(&f.FilterVlanID, "filter-vlan-id", "V", 0, "filter VLAN ID")
	flag.Uint32VarP(&f.FilterVxlanVNI, "filter-vxlan-vni", "X", 0, "filter VxLAN VNI")

	flag.Uint32VarP(&f.FilterMark, "filter-mark", "M", 0, "filter mark")

	flag.StringVarP(&f.FilterSaddr, "filter-saddr", "S", "", "filter source address")
	flag.StringVarP(&f.FilterDaddr, "filter-daddr", "D", "", "filter destination address")
	flag.StringVarP(&f.FilterAddr, "filter-addr", "A", "", "filter source or destination address with lower priority of --filter-saddr and --filter-daddr")

	flag.Uint16Var(&f.FilterSport, "filter-sport", 0, "filter source port of TCP/UDP")
	flag.Uint16Var(&f.FilterDport, "filter-dport", 0, "filter destination port of TCP/UDP")
	flag.Uint16VarP(&f.FilterPort, "filter-port", "P", 0, "filter source or destination port of TCP/UDP")

	flag.StringVar(&f.FilterProto, "filter-proto", "", "filter l4 protocol, only TCP/UDP/ICMP")

	flag.BoolVar(&f.ClearTcQdisc, "clear-tc-qdisc", false, "clear tc-qdisc when exit")

	flag.Parse()

	return &f
}

func (f *flags) getDevices() map[int]string {
	links, err := netlink.LinkList()
	if err != nil {
		log.Fatalf("Failed to list links: %v", err)
	}

	m := make(map[int]string)
	if len(f.Devices) == 0 {
		for _, l := range links {
			ifindex, ifname := l.Attrs().Index, l.Attrs().Name
			m[ifindex] = ifname
		}

		return m
	}

	target := make(map[string]struct{}, len(f.Devices))
	for _, dev := range f.Devices {
		target[dev] = struct{}{}
	}
	for _, l := range links {
		ifindex, ifname := l.Attrs().Index, l.Attrs().Name
		if _, ok := target[ifname]; ok {
			m[ifindex] = ifname
		}
	}

	return m
}
