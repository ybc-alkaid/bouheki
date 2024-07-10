package pipe

import (
	"encoding/binary"
	"strconv"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/mrtc0/bouheki/pkg/config"
)

const (
	PIPE_CONFIG = "pipe_bouheki_config_map"
	MODE_MONITOR      = uint32(0)
	MODE_BLOCK        = uint32(1)

	TARGET_HOST      = uint32(0)
	TARGET_CONTAINER = uint32(1)
)

type Manager struct {
	mod    *libbpfgo.Module
	config *config.Config
	pb     *libbpfgo.PerfBuffer
}

func (m *Manager) Start(eventChannel chan []byte, lostChannel chan uint64) error {
	pb, err := m.mod.InitPerfBuf("pipe_events", eventChannel, lostChannel, 1024)
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
	progEnter, err := m.mod.GetProgram(BPF_PROGRAM_NAME)
	if err != nil {
		return err
	}

	_, err = progEnter.AttachLSM()
	if err != nil {
		return err
	}
	return nil
}

func (m *Manager) SetConfigToMap() error {
	err := m.setModeAndTarget()
	if err != nil {
		return err
	}
	return nil
}

func (m *Manager) setModeAndTarget() error {
	key := make([]byte, 8)
	configMap, err := m.mod.GetMap(PIPE_CONFIG)
	if err != nil {
		return err
	}

	if m.config.IsRestrictedMode("pipe") {
		binary.LittleEndian.PutUint32(key[0:4], MODE_BLOCK)
	} else {
		binary.LittleEndian.PutUint32(key[0:4], MODE_MONITOR)
	}

	if m.config.IsOnlyContainer("pipe") {
		binary.LittleEndian.PutUint32(key[4:8], TARGET_CONTAINER)
	} else {
		binary.LittleEndian.PutUint32(key[4:8], TARGET_HOST)
	}

	k := uint8(0)
	err = configMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&key[0]))
	if err != nil {
		return err
	}

	return nil
}
