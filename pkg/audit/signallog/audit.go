package signallog

import (
	"context"
	"sync"

	"github.com/aquasecurity/libbpfgo"
	"github.com/mrtc0/bouheki/pkg/config"
	log "github.com/mrtc0/bouheki/pkg/log"
)

func RunAudit(ctx context.Context, wg *sync.WaitGroup, conf *config.Config) error {
	defer wg.Done()

	// Enable verbose logging
	// libbpfgo.SetLogger(libbpfgo.NewDefaultLogger())

	// Load the BPF object file
	bpfModule, err := libbpfgo.NewModuleFromFile("/home/vagrant/bouheki-test/bouheki/pkg/bpf/bytecode/log-signal.bpf.o")
	if err != nil {
		log.Fatal(err)
		return err
	}
	defer bpfModule.Close()

	// Load the BPF program
	if err := bpfModule.BPFLoadObject(); err != nil {
		log.Fatal(err)
		return err
	}

	// Attach the BPF program to the tracepoint
	prog, err := bpfModule.GetProgram("sys_enter_kill")
	if err != nil {
		log.Fatal(err)
		return err
	}

	_, err = prog.AttachTracepoint("syscalls", "sys_enter_kill")
	if err != nil {
		log.Fatal(err)
		return err
	}

	log.Info("BPF program loaded and attached successfully")

	// Wait for the context to be done
	<-ctx.Done()
	log.Info("Stopping BPF program")
	return nil
}
