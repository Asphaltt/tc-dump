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
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jschwinger233/elibpcap"
	"golang.org/x/sync/errgroup"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcDump ./ebpf/tc_dump.c -- -D__TARGET_ARCH_x86 -I./ebpf/headers -Wall

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	flags := parseFlags()
	cfg := newConfig(flags)
	devs := flags.getDevices()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec, err := loadTcDump()
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
	}

	eventMapSpec := spec.Maps["events"]
	eventMap, err := ebpf.NewMap(eventMapSpec)
	if err != nil {
		log.Fatalf("Failed to create perf-event map: %v", err)
	}
	defer eventMap.Close()

	progSpec := spec.Programs["on_ingress"]
	progSpec.Instructions, err = elibpcap.Inject(flags.PcapFilterExpr,
		progSpec.Instructions, elibpcap.Options{
			AtBpf2Bpf:  "filter_pcap_ebpf_l2",
			DirectRead: true,
			L2Skb:      true,
		})
	if err != nil {
		log.Fatalf("Failed to inject pcap filter: %v", err)
	}
	progSpec = spec.Programs["on_egress"]
	progSpec.Instructions, err = elibpcap.Inject(flags.PcapFilterExpr,
		progSpec.Instructions, elibpcap.Options{
			AtBpf2Bpf:  "filter_pcap_ebpf_l2",
			DirectRead: true,
			L2Skb:      true,
		})
	if err != nil {
		log.Fatalf("Failed to inject pcap filter: %v", err)
	}

	rewriteConst := map[string]interface{}{
		"__cfg": *cfg,
	}

	wg, ctx := errgroup.WithContext(ctx)
	for ifindex, ifname := range devs {
		rewriteConst["IFINDEX"] = uint32(ifindex)

		if err := spec.RewriteConstants(rewriteConst); err != nil {
			log.Fatalf("Failed to rewrite const for if@%d:%s: %v", ifindex, ifname, err)
		}

		var obj tcDumpObjects
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
		defer obj.Close()

		ifidx, ifname := ifindex, ifname
		wg.Go(func() error {
			runTcDump(ctx, &obj, ifidx, ifname, flags.KeepTcQdisc)
			return nil
		})
	}

	wg.Go(func() error {
		handlePerfEvent(ctx, eventMap, devs)
		return nil
	})

	_ = wg.Wait()
}

func runTcDump(ctx context.Context, obj *tcDumpObjects, ifindex int, ifname string, keepTcQdisc bool) {
	if err := replaceTcQdisc(ifindex); err != nil {
		log.Printf("Failed to replace tc-qdisc for if@%d:%s: %v", ifindex, ifname, err)
		return
	} else if !keepTcQdisc {
		defer deleteTcQdisc(ifindex)
	}

	if err := addTcFilterIngress(ifindex, obj.OnIngress); err != nil {
		log.Printf("Failed to add tc-filter ingress for if@%d:%s: %v", ifindex, ifname, err)
		return
	} else {
		defer deleteTcFilterIngress(ifindex, obj.OnIngress)
	}

	if err := addTcFilterEgress(ifindex, obj.OnEgress); err != nil {
		log.Printf("Failed to add tc-filter egress for if@%d:%s: %v", ifindex, ifname, err)
	} else {
		defer deleteTcFilterEgress(ifindex, obj.OnEgress)
	}

	log.Printf("Listening events for if@%d:%s...", ifindex, ifname)

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
