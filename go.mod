module github.com/Asphaltt/tc-dump

go 1.21.0

toolchain go1.21.3

require (
	github.com/cilium/ebpf v0.16.0
	github.com/florianl/go-tc v0.4.1
	github.com/jschwinger233/elibpcap v0.0.0-20231010035657-e99300096f5e
	github.com/spf13/pflag v1.0.5
	github.com/vishvananda/netlink v1.1.0
	golang.org/x/sync v0.1.0
	golang.org/x/sys v0.20.0
)

require (
	github.com/cloudflare/cbpfc v0.0.0-20230809125630-31aa294050ff // indirect
	github.com/ebitengine/purego v0.7.1 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df // indirect
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
	golang.org/x/net v0.23.0 // indirect
)

replace github.com/jschwinger233/elibpcap v0.0.0-20231010035657-e99300096f5e => github.com/Asphaltt/elibpcap-purego v0.0.0-20240921145056-d41d82f3f8b1
