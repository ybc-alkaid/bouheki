package signallog

import (
	"encoding/binary"
	"strconv"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/mrtc0/bouheki/pkg/config"
)

const (
	SINGNALLOG_CONFIG = "signallog_bouheki_config_map"
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
	progEnter, err := m.mod.GetProgram(BPF_ENTRY_PROGRAM_NAME)
	if err != nil {
		return err
	}

	_, err = progEnter.AttachTracepoint("syscalls", "sys_enter_kill")
	if err != nil {
		return err
	}

	progExit, err := m.mod.GetProgram(BPF_EXIT_PROGRAM_NAME)
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

func (m *Manager) SetConfigToMap() error {
	err := m.setModeAndTarget()
	if err != nil {
		return err
	}

	err = m.setAllowedTypesMap()
	if err != nil {
		return err
	}

	err = m.setDeniedTypesMap()
	if err != nil {
		return err
	}

	return nil
}

func (m *Manager) setModeAndTarget() error {
	key := make([]byte, 8)
	configMap, err := m.mod.GetMap(SINGNALLOG_CONFIG)
	if err != nil {
		return err
	}

	if m.config.IsRestrictedMode("signallog") {
		binary.LittleEndian.PutUint32(key[0:4], MODE_BLOCK)
	} else {
		binary.LittleEndian.PutUint32(key[0:4], MODE_MONITOR)
	}

	if m.config.IsOnlyContainer("signallog") {
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
func (m *Manager) setAllowedTypesMap() error {
	map_allowed_files, err := m.mod.GetMap(ALLOWED_TYPES_MAP_NAME)
	if err != nil {
		return err
	}

	allowed_types := m.config.SignalLogConfig.Type.Allow

	for i, sig_type := range allowed_types {
		key := uint8(i)
		value := []byte(sig_type)
		err = map_allowed_files.Update(unsafe.Pointer(&key), unsafe.Pointer(&value[0]))
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) setDeniedTypesMap() error {
	mapDeniedSignals, err := m.mod.GetMap(DENIED_TYPES_MAP_NAME)
	if err != nil {
		return err
	}
	deniedTypes := m.config.SignalLogConfig.Type.Deny

	for i, sigType := range deniedTypes {
		key := uint32(i)
		num, err := strconv.ParseInt(sigType, 10, 32)
		if err != nil {
			return err
		}

		value := int32(num)

		keyPtr := unsafe.Pointer(&key)
		valuePtr := unsafe.Pointer(&value)
		err = mapDeniedSignals.Update(keyPtr, valuePtr)
		if err != nil {
			return err
		}
	}

	return nil
}
