package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
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

	var wg sync.WaitGroup
	rewriteConst := map[string]interface{}{
		"__cfg": *cfg,
	}

	for ifindex, ifname := range devs {
		rewriteConst["IFINDEX"] = uint32(ifindex)

		if err := spec.RewriteConstants(rewriteConst); err != nil {
			log.Fatalf("Failed to rewrite const for if@%d:%s: %v", ifindex, ifname, err)
		}

		var obj tcDumpObjects
		if err := spec.LoadAndAssign(&obj, &ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: ebpf.DefaultVerifierLogSize * 4,
			},
		}); err != nil {
			log.Fatalf("Failed to load bpf obj for if@%d:%s: %v", ifindex, ifname, err)
		}

		wg.Add(1)
		go func(obj *tcDumpObjects, ifindex int, ifname string) {
			defer wg.Done()
			runTcDump(ctx, obj, ifindex, ifname, flags, devs)
		}(&obj, ifindex, ifname)
	}

	<-ctx.Done()
	wg.Wait()
}

func runTcDump(ctx context.Context, obj *tcDumpObjects, ifindex int, ifname string, flags *flags, devs map[int]string) {
	if err := replaceTcQdisc(ifindex); err != nil {
		log.Printf("Failed to replace tc-qdisc for if@%d:%s: %v", ifindex, ifname, err)
		return
	} else if flags.ClearTcQdisc {
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

	handlePerfEvent(ctx, obj.Events, ifindex, ifname, devs)
}

func handlePerfEvent(ctx context.Context, events *ebpf.Map, ifindex int, ifname string, devs map[int]string) {
	eventReader, err := perf.NewReader(events, 4096)
	if err != nil {
		log.Printf("Failed to create perf-event reader for if@%d:%s: %v", ifindex, ifname, err)
		return
	}

	log.Printf("Listening events for if@%d:%s...", ifindex, ifname)

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
