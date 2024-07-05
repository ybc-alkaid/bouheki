package signallog

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"sync"

	"github.com/aquasecurity/libbpfgo"
	"github.com/mrtc0/bouheki/pkg/bpf"
	"github.com/mrtc0/bouheki/pkg/config"
	log "github.com/mrtc0/bouheki/pkg/log"
)

const (
	TASK_COMM_LEN = 16
)

type Event struct {
	Pid  uint32
	Tpid uint32
	Sig  int32
	Ret  int32
	Comm [TASK_COMM_LEN]byte
}

func setupBPFProgram() (*libbpfgo.Module, error) {
	bytecode, err := bpf.EmbedFS.ReadFile("bytecode/log-signal.bpf.o")
	if err != nil {
		return nil, err
	}
	mod, err := libbpfgo.NewModuleFromBuffer(bytecode, "log-signal")
	if err != nil {
		return nil, err
	}

	if err = mod.BPFLoadObject(); err != nil {
		return nil, err
	}

	return mod, nil
}

func RunAudit(ctx context.Context, wg *sync.WaitGroup, conf *config.Config) error {
	log.Info("Launching the signal audit...")
	defer wg.Done()

	mod, err := setupBPFProgram()
	if err != nil {
		log.Fatal(err)
	}
	defer mod.Close()

	mgr := Manager{
		mod:    mod,
		config: conf,
	}

	if err := mgr.Attach(); err != nil {
		log.Fatal(err)
	}

	log.Info("Start the signal audit.")
	eventChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	if err := mgr.Start(eventChannel, lostChannel); err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			select {
			case eventBytes := <-eventChannel:
				event, err := parseEvent(eventBytes)
				if err != nil {
					log.Error(err)
					continue
				}
				hostname, _ := os.Hostname()
				signalLog := log.SignalLog{
					Action:   "Signal sent",
					Hostname: hostname,
					PID:      event.Pid,
					Tpid:     event.Tpid,
					Sig:      event.Sig,
					Ret:      event.Ret,
					Comm:     trimNullChars(event.Comm[:]),
				}
				signalLog.Info()
			case <-lostChannel:
				log.Info("Lost events")
			case <-ctx.Done():
				log.Info("Stopping signal audit")
				return
			}
		}
	}()

	<-ctx.Done()
	// mgr.Close()
	log.Info("Terminated the signal audit.")

	return nil
}

func parseEvent(eventBytes []byte) (Event, error) {
	var event Event
	buf := bytes.NewBuffer(eventBytes)
	err := binary.Read(buf, binary.LittleEndian, &event)
	if err != nil {
		return Event{}, err
	}
	return event, nil
}

// Helper function to trim null characters from a byte array
func trimNullChars(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		return string(b)
	}
	return string(b[:n])
}
