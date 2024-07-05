package signallog

import (
	"github.com/aquasecurity/libbpfgo"
	"github.com/mrtc0/bouheki/pkg/config"
)

type Manager struct {
	mod    *libbpfgo.Module
	config *config.Config
	pb     *libbpfgo.PerfBuffer
}

func (m *Manager) Start(eventChannel chan []byte, lostChannel chan uint64) error {
	pb, err := m.mod.InitPerfBuf("signal_events", eventChannel, lostChannel, 1024)
	if err != nil {
		return err
	}

	pb.Start()
	m.pb = pb

	return nil
}

func (m *Manager) Stop() {
	m.pb.Stop()
}

func (m *Manager) Close() {
	m.pb.Close()
}

func (m *Manager) Attach() error {
	progEnter, err := m.mod.GetProgram("kill_entry")
	if err != nil {
		return err
	}

	_, err = progEnter.AttachTracepoint("syscalls", "sys_enter_kill")
	if err != nil {
		return err
	}

	progExit, err := m.mod.GetProgram("kill_exit")
	if err != nil {
		return err
	}

	_, err = progExit.AttachTracepoint("syscalls", "sys_exit_kill")
	if err != nil {
		return err
	}

	// log.Debug(fmt.Sprintf("%s attached.", "kill_entry and kill_exit"))
	return nil
}
