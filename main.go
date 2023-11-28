package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jschwinger233/elibpcap"
	"golang.org/x/sync/errgroup"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcDump ./ebpf/tc_dump.c -- -D__TARGET_ARCH_x86 -I./ebpf/headers -Wall -g -O2 -mcpu=v3
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang fentryTc ./ebpf/fentry_tc.c -- -D__TARGET_ARCH_x86 -I./ebpf/headers -Wall -g -O2 -mcpu=v3

const (
	DirectionIngress = 1
	DirectionEgress  = 2

	DirIngress = "INGRESS"
	DirEgress  = "EGRESS"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	flags := parseFlags()
	cfg := newConfig(flags)
	devs := flags.getDevices()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	specTc, err := loadTcDump()
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
	}

	eventMapSpec := specTc.Maps["events"]
	eventMap, err := ebpf.NewMap(eventMapSpec)
	if err != nil {
		log.Fatalf("Failed to create perf-event map: %v", err)
	}
	defer eventMap.Close()

	progSpec := specTc.Programs["on_ingress"]
	progSpec.Instructions, err = elibpcap.Inject(flags.PcapFilterExpr,
		progSpec.Instructions, elibpcap.Options{
			AtBpf2Bpf:  "filter_pcap_ebpf_l2",
			DirectRead: true,
			L2Skb:      true,
		})
	if err != nil {
		log.Fatalf("Failed to inject pcap filter: %v", err)
	}
	progSpec = specTc.Programs["on_egress"]
	progSpec.Instructions, err = elibpcap.Inject(flags.PcapFilterExpr,
		progSpec.Instructions, elibpcap.Options{
			AtBpf2Bpf:  "filter_pcap_ebpf_l2",
			DirectRead: true,
			L2Skb:      true,
		})
	if err != nil {
		log.Fatalf("Failed to inject pcap filter: %v", err)
	}

	specFentry, err := loadFentryTc()
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
	}

	progSpec = specFentry.Programs["fentry_tc"]
	progSpec.Instructions, err = elibpcap.Inject(flags.PcapFilterExpr,
		progSpec.Instructions, elibpcap.Options{
			AtBpf2Bpf:  "filter_pcap_ebpf_l2",
			DirectRead: false,
			L2Skb:      true,
		})
	if err != nil {
		log.Fatalf("Failed to inject pcap filter: %v", err)
	}

	rewriteConst := map[string]interface{}{
		"__cfg": *cfg,
	}

	wg, ctx := errgroup.WithContext(ctx)

	for idx := range devs {
		ifindex, ifname := idx, devs[idx]
		rewriteConst["IFINDEX"] = uint32(ifindex)

		progIngress, okIngress, err := checkTcFilter(ifindex, true)
		if err != nil {
			log.Fatalf("Failed to check tc filter ingress for if@%d:%s: %v", ifindex, ifname, err)
		}

		progEgress, okEgress, err := checkTcFilter(ifindex, false)
		if err != nil {
			log.Fatalf("Failed to check tc filter egress for if@%d:%s: %v", ifindex, ifname, err)
		}

		if okIngress {
			defer progIngress.Close()
			obj, err := attachFentryTc(progIngress, eventMap, specFentry, rewriteConst, ifindex, ifname, true)
			if err != nil {
				log.Fatalf("Failed to attach fentry-tc for if@%d:%s %s: %v", ifindex, ifname, DirIngress, err)
			}
			defer obj.Close()

			wg.Go(func() error {
				runFentryTc(ctx, obj, ifindex, ifname, true)
				return nil
			})
		}

		if okEgress {
			defer progEgress.Close()
			obj, err := attachFentryTc(progEgress, eventMap, specFentry, rewriteConst, ifindex, ifname, false)
			if err != nil {
				log.Fatalf("Failed to attach fentry-tc for if@%d:%s %s: %v", ifindex, ifname, DirEgress, err)
			}
			defer obj.Close()

			wg.Go(func() error {
				runFentryTc(ctx, obj, ifindex, ifname, false)
				return nil
			})
		}

		if !okIngress || !okEgress {
			if err := specTc.RewriteConstants(rewriteConst); err != nil {
				log.Fatalf("Failed to rewrite const for if@%d:%s: %v", ifindex, ifname, err)
			}

			var obj tcDumpObjects
			if err := specTc.LoadAndAssign(&obj, &ebpf.CollectionOptions{
				MapReplacements: map[string]*ebpf.Map{
					"events": eventMap,
				},
				Programs: ebpf.ProgramOptions{
					LogSize: ebpf.DefaultVerifierLogSize * 4,
				},
			}); err != nil {
				var ve *ebpf.VerifierError
				if errors.As(err, &ve) {
					log.Printf("Failed to load bpf obj for if@%d:%s: %v\n%+v", ifindex, ifname, err, ve)
				}
				log.Fatalf("Failed to load bpf obj for if@%d:%s: %v", ifindex, ifname, err)
			}
			defer obj.Close()

			wg.Go(func() error {
				runTcDump(ctx, &obj, ifindex, ifname, !okIngress, !okEgress, flags.KeepTcQdisc)
				return nil
			})
		}

	}

	wg.Go(func() error {
		handlePerfEvent(ctx, eventMap, devs)
		return nil
	})

	_ = wg.Wait()
}

func runTcDump(ctx context.Context, obj *tcDumpObjects, ifindex int, ifname string,
	withIngress, withEgress, keepTcQdisc bool,
) {
	if !withIngress && !withEgress {
		return
	}

	if err := replaceTcQdisc(ifindex); err != nil {
		log.Printf("Failed to replace tc-qdisc for if@%d:%s: %v", ifindex, ifname, err)
		return
	} else if !keepTcQdisc {
		defer deleteTcQdisc(ifindex)
	}

	if withIngress {
		if err := addTcFilterIngress(ifindex, obj.OnIngress); err != nil {
			log.Printf("Failed to add tc-filter ingress for if@%d:%s: %v", ifindex, ifname, err)
			return
		} else {
			defer deleteTcFilterIngress(ifindex, obj.OnIngress)
		}

		log.Printf("Listening events for if@%d:%s %s by TC...", ifindex, ifname, DirIngress)
	}

	if withEgress {
		if err := addTcFilterEgress(ifindex, obj.OnEgress); err != nil {
			log.Printf("Failed to add tc-filter egress for if@%d:%s: %v", ifindex, ifname, err)
			return
		} else {
			defer deleteTcFilterEgress(ifindex, obj.OnEgress)
		}

		log.Printf("Listening events for if@%d:%s %s by TC...", ifindex, ifname, DirEgress)
	}

	<-ctx.Done()
}

func copyMap(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func attachFentryTc(prog *ebpf.Program, eventMap *ebpf.Map, spec *ebpf.CollectionSpec, rc map[string]any,
	ifindex int, ifname string, isIngress bool,
) (*fentryTcObjects, error) {
	dir := uint16(DirectionEgress)
	if isIngress {
		dir = uint16(DirectionIngress)
	}

	rewriteConst := copyMap(rc)
	rewriteConst["DIR"] = dir

	if err := spec.RewriteConstants(rewriteConst); err != nil {
		log.Fatalf("Failed to rewrite const for if@%d:%s: %v", ifindex, ifname, err)
	}

	progEntry, err := getEntryFuncName(prog)
	if err != nil {
		log.Fatalf("Failed to get entry func name for if@%d:%s: %v", ifindex, ifname, err)
	}

	progSpec := spec.Programs["fentry_tc"]
	progSpec.AttachTarget = prog
	progSpec.AttachTo = progEntry

	var obj fentryTcObjects
	if err := spec.LoadAndAssign(&obj, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"events": eventMap,
		},
		Programs: ebpf.ProgramOptions{
			LogSize: ebpf.DefaultVerifierLogSize * 4,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("Failed to load bpf obj for if@%d:%s: %v\n%+v", ifindex, ifname, err, ve)
		}
		log.Fatalf("Failed to load bpf obj for if@%d:%s: %v", ifindex, ifname, err)
	}

	return &obj, nil
}

func runFentryTc(ctx context.Context, obj *fentryTcObjects, ifindex int, ifname string, isIngress bool) {
	var direction string
	if isIngress {
		direction = DirIngress
	} else {
		direction = DirEgress
	}

	fentry, err := link.AttachTracing(link.TracingOptions{
		Program: obj.FentryTc,
	})
	if err != nil {
		log.Printf("Failed to attach fentry-tc for if@%d:%s %s: %v", ifindex, ifname, direction, err)
		return
	}
	defer fentry.Close()

	log.Printf("Listening events for if@%d:%s %s by Fentry...", ifindex, ifname, direction)

	<-ctx.Done()
}

func handlePerfEvent(ctx context.Context, events *ebpf.Map, devs map[int]string) {
	eventReader, err := perf.NewReader(events, 4096)
	if err != nil {
		log.Printf("Failed to create perf-event reader : %v", err)
		return
	}

	go func() {
		<-ctx.Done()
		eventReader.Close()
	}()

	var ev event
	for {
		event, err := eventReader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}

			log.Printf("Reading perf-event: %v", err)
		}

		if event.LostSamples != 0 {
			log.Printf("Lost %d events", event.LostSamples)
		}

		binary.Read(bytes.NewBuffer(event.RawSample), binary.LittleEndian, &ev)

		ev.output(devs)

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
