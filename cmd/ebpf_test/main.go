package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"detonator/internal/sensor"
)

// Quick standalone test to verify eBPF tracepoints work.
// Captures ALL syscalls (debug mode) for 5 seconds and prints them.
// Usage: sudo go run ./cmd/ebpf_test/
func main() {
	fmt.Println("=== eBPF Tracepoint Debug Test ===")
	fmt.Println("Capturing ALL syscalls for 5 seconds...")
	fmt.Println()

	// Check root
	if os.Geteuid() != 0 {
		fmt.Println("ERROR: Must run as root (sudo)")
		os.Exit(1)
	}

	// Create sensor
	s, err := sensor.New()
	if err != nil {
		fmt.Printf("Failed to create sensor: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()

	// Enable debug mode (capture everything)
	if err := s.SetDebugMode(); err != nil {
		fmt.Printf("Failed to set debug mode: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ eBPF sensor loaded and attached")
	fmt.Println("✓ Debug mode: capturing ALL syscalls")
	fmt.Println()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := s.Start(ctx)
	if err != nil {
		fmt.Printf("Failed to start: %v\n", err)
		os.Exit(1)
	}

	execveCount := 0
	openatCount := 0

	for ev := range ch {
		switch ev.EventType {
		case sensor.EventExecve:
			execveCount++
			if execveCount <= 20 {
				fmt.Printf("[EXECVE] PID=%d PPID=%d comm=%s file=%s\n", ev.PID, ev.PPID, ev.ProcessName, ev.Filename)
			}
		case sensor.EventOpenat:
			openatCount++
			if openatCount <= 10 {
				fmt.Printf("[OPENAT] PID=%d comm=%s file=%s\n", ev.PID, ev.ProcessName, ev.Filename)
			}
		}
	}

	fmt.Println()
	fmt.Printf("=== Results: %d EXECVE, %d OPENAT events in 5 seconds ===\n", execveCount, openatCount)
}
