package sensor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// EventType identifies the kind of syscall captured.
type EventType uint32

const (
	EventExecve  EventType = 1
	EventOpenat  EventType = 2
	EventConnect EventType = 3
	EventWrite   EventType = 4
	EventUnlink  EventType = 5
)

// String returns a human-readable name for the event type.
func (e EventType) String() string {
	switch e {
	case EventExecve:
		return "EXECVE"
	case EventOpenat:
		return "OPENAT"
	case EventConnect:
		return "CONNECT"
	case EventWrite:
		return "WRITE"
	case EventUnlink:
		return "UNLINK"
	default:
		return "UNKNOWN"
	}
}

// SyscallEvent is the parsed Go representation of an eBPF event.
type SyscallEvent struct {
	PID         uint32    `json:"pid"`
	PPID        uint32    `json:"ppid"`
	TimestampNs uint64    `json:"timestamp_ns"`
	EventType   EventType `json:"event_type"`
	ProcessName string    `json:"process_name"`
	Filename    string    `json:"filename"`
	ConnectPort uint32    `json:"connect_port,omitempty"`
	ConnectIP   uint32    `json:"connect_ip,omitempty"`
	WriteBytes  uint64    `json:"write_bytes,omitempty"`
	WriteFD     int32     `json:"write_fd,omitempty"`
}

// Sensor manages the eBPF lifecycle: loading probes, attaching to tracepoints,
// and reading events from the ring buffer.
type Sensor struct {
	objs       probeObjects
	tpExecve   link.Link
	tpOpenat   link.Link
	tpOpen     link.Link
	tpFork     link.Link
	tpConnect  link.Link
	tpWrite    link.Link
	tpUnlinkat link.Link
	reader     *ringbuf.Reader
	mu         sync.Mutex
}

// New creates and initializes a new eBPF sensor.
// The sensor attaches to kernel tracepoints immediately but does NOT capture
// any events until SetContainerID() is called and PIDs are synced.
// Requires root privileges (or CAP_BPF + CAP_PERFMON).
func New() (*Sensor, error) {
	// Remove the memlock rlimit — required for eBPF on kernels < 5.11,
	// harmless on newer kernels.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock: %w", err)
	}

	// Load the compiled eBPF objects (programs + maps).
	var objs probeObjects
	if err := loadProbeObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading eBPF objects: %w", err)
	}

	// Attach to tracepoint: sys_enter_execve
	tpExecve, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching execve tracepoint: %w", err)
	}

	// Attach to tracepoint: sys_enter_openat
	tpOpenat, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleOpenat, nil)
	if err != nil {
		tpExecve.Close()
		objs.Close()
		return nil, fmt.Errorf("attaching openat tracepoint: %w", err)
	}

	// Attach to tracepoint: sched_process_fork
	tpFork, err := link.Tracepoint("sched", "sched_process_fork", objs.HandleProcessFork, nil)
	if err != nil {
		tpOpenat.Close()
		tpExecve.Close()
		objs.Close()
		return nil, fmt.Errorf("attaching sched_process_fork tracepoint: %w", err)
	}

	// Attach to tracepoint: sys_enter_open
	tpOpen, err := link.Tracepoint("syscalls", "sys_enter_open", objs.HandleOpen, nil)
	if err != nil {
		tpFork.Close()
		tpOpenat.Close()
		tpExecve.Close()
		objs.Close()
		return nil, fmt.Errorf("attaching open tracepoint: %w", err)
	}

	// Attach to tracepoint: sys_enter_connect
	tpConnect, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.HandleConnect, nil)
	if err != nil {
		tpOpen.Close()
		tpFork.Close()
		tpOpenat.Close()
		tpExecve.Close()
		objs.Close()
		return nil, fmt.Errorf("attaching connect tracepoint: %w", err)
	}

	// Attach to tracepoint: sys_enter_write
	tpWrite, err := link.Tracepoint("syscalls", "sys_enter_write", objs.HandleWrite, nil)
	if err != nil {
		tpConnect.Close()
		tpOpen.Close()
		tpFork.Close()
		tpOpenat.Close()
		tpExecve.Close()
		objs.Close()
		return nil, fmt.Errorf("attaching write tracepoint: %w", err)
	}

	// Attach to tracepoint: sys_enter_unlinkat
	tpUnlinkat, err := link.Tracepoint("syscalls", "sys_enter_unlinkat", objs.HandleUnlinkat, nil)
	if err != nil {
		tpWrite.Close()
		tpConnect.Close()
		tpOpen.Close()
		tpFork.Close()
		tpOpenat.Close()
		tpExecve.Close()
		objs.Close()
		return nil, fmt.Errorf("attaching unlinkat tracepoint: %w", err)
	}

	// Open the ring buffer reader.
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		tpUnlinkat.Close()
		tpWrite.Close()
		tpConnect.Close()
		tpOpen.Close()
		tpFork.Close()
		tpOpenat.Close()
		tpExecve.Close()
		objs.Close()
		return nil, fmt.Errorf("opening ring buffer: %w", err)
	}

	return &Sensor{
		objs:       objs,
		tpExecve:   tpExecve,
		tpOpenat:   tpOpenat,
		tpOpen:     tpOpen,
		tpFork:     tpFork,
		tpConnect:  tpConnect,
		tpWrite:    tpWrite,
		tpUnlinkat: tpUnlinkat,
		reader:     reader,
	}, nil
}


// Start begins reading eBPF events and sends them to the returned channel.
// The channel is closed when the sensor stops.
func (s *Sensor) Start(ctx context.Context) (<-chan SyscallEvent, error) {
	ch := make(chan SyscallEvent, 256)

	// Ring buffer reader
	go func() {
		defer close(ch)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			record, err := s.reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}

			var raw probeEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &raw); err != nil {
				continue
			}

			event := SyscallEvent{
				PID:         raw.Pid,
				PPID:        raw.Ppid,
				TimestampNs: raw.TimestampNs,
				EventType:   EventType(raw.EventType),
				ProcessName: int8SliceToString(raw.Comm[:]),
				Filename:    int8SliceToString(raw.Filename[:]),
				ConnectPort: raw.ConnectPort,
				ConnectIP:   raw.ConnectIp,
				WriteBytes:  raw.WriteBytes,
				WriteFD:     raw.WriteFd,
			}

			// Since we use sched_process_fork to track child processes,
			// the eBPF program updates the AllowedPids map automatically!
			// We no longer need to track user-space state.

			select {
			case ch <- event:
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
				// Drop event if channel is full
			}
		}
	}()

	return ch, nil
}

// TrackedPIDCount returns the number of host PIDs currently being monitored.
func (s *Sensor) TrackedPIDCount() int {
	var pid uint32
	var marker uint8
	count := 0
	
	iter := s.objs.AllowedPids.Iterate()
	for iter.Next(&pid, &marker) {
		count++
	}
	return count
}

// Close shuts down the sensor.
func (s *Sensor) Close() {
	if s.reader != nil {
		s.reader.Close()
	}
	if s.tpExecve != nil {
		s.tpExecve.Close()
	}
	if s.tpOpenat != nil {
		s.tpOpenat.Close()
	}
	if s.tpOpen != nil {
		s.tpOpen.Close()
	}
	if s.tpFork != nil {
		s.tpFork.Close()
	}
	if s.tpConnect != nil {
		s.tpConnect.Close()
	}
	if s.tpWrite != nil {
		s.tpWrite.Close()
	}
	if s.tpUnlinkat != nil {
		s.tpUnlinkat.Close()
	}
	s.objs.Close()
}

// int8SliceToString converts a null-terminated int8 slice (from the C char array)
// to a Go string. bpf2go maps C char to Go int8.
func int8SliceToString(s []int8) string {
	buf := make([]byte, 0, len(s))
	for _, c := range s {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
}
