package detonator

import (
	"context"
	"fmt"
	"strings"
	"time"

	"detonator/internal/config"
	"detonator/internal/orchestrator"
)

// ANSI color codes for terminal output.
const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
	BgRed   = "\033[41m"
	BgGreen = "\033[42m"
)

// DetonationResult holds the forensic report from a detonation run.
type DetonationResult struct {
	PackageName string        `json:"package_name"`
	Registry    string        `json:"registry"`
	ContainerID string        `json:"container_id"`
	ContainerPID int          `json:"container_pid"`
	StartTime   time.Time     `json:"start_time"`
	EndTime     time.Time     `json:"end_time"`
	Duration    time.Duration `json:"duration"`
	Logs        string        `json:"logs"`
	Success     bool          `json:"success"`
	Error       string        `json:"error,omitempty"`
}

// step prints a formatted step indicator.
func step(num, total int, msg string) {
	fmt.Printf("  %s[%d/%d]%s %s", Cyan+Bold, num, total, Reset, msg)
}

// done prints a success checkmark.
func done() {
	fmt.Printf("  %s✓%s\n", Green+Bold, Reset)
}

// fail prints a failure X.
func fail(err error) {
	fmt.Printf("  %s✗%s  %s%s%s\n", Red+Bold, Reset, Dim, err.Error(), Reset)
}

// printBanner displays the startup banner.
func printBanner(cfg *config.Config) {
	fmt.Println()
	fmt.Printf("  %s%s╔══════════════════════════════════════════════════════════════╗%s\n", Bold, Red, Reset)
	fmt.Printf("  %s%s║       ☢  NPM SUPPLY CHAIN DETONATION SANDBOX  ☢           ║%s\n", Bold, Red, Reset)
	fmt.Printf("  %s%s║                       v0.1.0                                ║%s\n", Bold, Red, Reset)
	fmt.Printf("  %s%s╚══════════════════════════════════════════════════════════════╝%s\n", Bold, Red, Reset)
	fmt.Println()
	fmt.Printf("  %s[●]%s Target:    %s%s%s\n", Yellow, Reset, Bold+White, cfg.PackageName, Reset)
	fmt.Printf("  %s[●]%s Registry:  %s%s%s\n", Yellow, Reset, Bold+White, cfg.Registry, Reset)
	fmt.Printf("  %s[●]%s Timeout:   %s%s%s\n", Yellow, Reset, Bold+White, cfg.DetonationTimeout, Reset)
	fmt.Printf("  %s[●]%s Network:   %s%sDISABLED%s\n", Yellow, Reset, Bold, BgRed+White, Reset)
	fmt.Printf("  %s[●]%s Memory:    %s%dMB%s\n", Yellow, Reset, Bold+White, cfg.MemoryLimitMB, Reset)
	fmt.Printf("  %s[●]%s PID Limit: %s%d%s\n", Yellow, Reset, Bold+White, cfg.PidsLimit, Reset)
	fmt.Println()
	fmt.Printf("  %s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", Dim, Reset)
	fmt.Println()
}

// printReport displays the post-detonation forensic report.
func printReport(result *DetonationResult) {
	fmt.Println()
	fmt.Printf("  %s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", Dim, Reset)
	fmt.Println()

	statusColor := Green
	statusText := "DETONATION COMPLETE"
	if !result.Success {
		statusColor = Red
		statusText = "DETONATION FAILED"
	}

	fmt.Printf("  %s%s%s %s %s\n", Bold, statusColor, statusText, Reset, "")
	fmt.Println()
	fmt.Printf("  %sContainer ID:%s  %s\n", Dim, Reset, result.ContainerID[:12])
	fmt.Printf("  %sContainer PID:%s %d\n", Dim, Reset, result.ContainerPID)
	fmt.Printf("  %sDuration:%s      %s\n", Dim, Reset, result.Duration.Round(time.Millisecond))
	fmt.Printf("  %sLog Lines:%s     %d\n", Dim, Reset, countLines(result.Logs))
	fmt.Println()

	if result.Logs != "" {
		fmt.Printf("  %s%sFORENSIC LOG:%s\n", Bold, Magenta, Reset)
		fmt.Printf("  %s────────────────────────────────────────────────%s\n", Dim, Reset)
		lines := strings.Split(strings.TrimSpace(result.Logs), "\n")
		maxLines := 30
		start := 0
		if len(lines) > maxLines {
			start = len(lines) - maxLines
			fmt.Printf("  %s... (%d lines truncated) ...%s\n", Dim, start, Reset)
		}
		for _, line := range lines[start:] {
			// Strip Docker multiplexing header bytes (first 8 bytes per frame)
			clean := stripDockerHeader(line)
			fmt.Printf("  %s│%s %s\n", Dim, Reset, clean)
		}
		fmt.Printf("  %s────────────────────────────────────────────────%s\n", Dim, Reset)
	}

	if result.Error != "" {
		fmt.Printf("\n  %s%sError: %s%s\n", Red, Bold, result.Error, Reset)
	}
	fmt.Println()
}

// Run executes the full detonation sequence.
func Run(ctx context.Context, cfg *config.Config) (*DetonationResult, error) {
	result := &DetonationResult{
		PackageName: cfg.PackageName,
		Registry:    string(cfg.Registry),
		StartTime:   time.Now(),
	}

	printBanner(cfg)

	totalSteps := 6

	// Step 1: Connect to Docker
	step(1, totalSteps, "Connecting to Docker daemon...")
	orch, err := orchestrator.New(cfg)
	if err != nil {
		fail(err)
		result.Error = err.Error()
		return result, err
	}
	defer orch.Close()

	if err := orch.Ping(ctx); err != nil {
		fail(err)
		result.Error = "Docker daemon unreachable: " + err.Error()
		return result, err
	}
	done()

	// Step 2: Pull image
	step(2, totalSteps, fmt.Sprintf("Pulling image %s%s%s...", Bold, cfg.Image(), Reset))
	if err := orch.PullImage(ctx); err != nil {
		fail(err)
		result.Error = err.Error()
		return result, err
	}
	done()

	// Step 3: Create detonation chamber
	step(3, totalSteps, "Creating detonation chamber...")
	containerID, err := orch.CreateChamber(ctx)
	if err != nil {
		fail(err)
		result.Error = err.Error()
		return result, err
	}
	result.ContainerID = containerID
	done()

	// Step 4: Detonate
	step(4, totalSteps, fmt.Sprintf("Injecting %s%s%s & detonating...", Bold+White, cfg.PackageName, Reset))
	fmt.Println()

	if err := orch.StartContainer(ctx, containerID); err != nil {
		fail(err)
		// Try cleanup
		_ = orch.Kill(ctx, containerID)
		result.Error = err.Error()
		return result, err
	}

	// Get the container PID for eBPF targeting (Phase 2)
	pid, err := orch.GetContainerPID(ctx, containerID)
	if err == nil {
		result.ContainerPID = pid
		fmt.Printf("       %s└─ Container PID: %d (for eBPF targeting)%s\n", Dim, pid, Reset)
	}

	fmt.Printf("       %s└─ %s %s", Dim, cfg.InstallCommand(), Reset)

	// Countdown timer
	timeout := cfg.DetonationTimeout
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	elapsed := time.Duration(0)

	for elapsed < timeout {
		select {
		case <-ticker.C:
			elapsed += time.Second
			remaining := timeout - elapsed
			fmt.Printf("\r       %s└─ ⏱  Detonation window: %s remaining   %s", Yellow, remaining, Reset)
		case <-ctx.Done():
			fmt.Println()
			result.Error = "context cancelled"
			_ = orch.Kill(ctx, containerID)
			return result, ctx.Err()
		}
	}
	fmt.Printf("\r       %s└─ ⏱  Detonation window: %sCOMPLETE%s              \n", Yellow, Green+Bold, Reset)

	// Step 5: Capture logs
	step(5, totalSteps, "Capturing forensic logs...")
	logs, err := orch.GetLogs(ctx, containerID)
	if err != nil {
		fail(err)
		// Non-fatal — continue to cleanup
		result.Error = err.Error()
	} else {
		result.Logs = logs
		done()
	}

	// Step 6: Kill container
	step(6, totalSteps, "Destroying detonation chamber...")
	if err := orch.Kill(ctx, containerID); err != nil {
		fail(err)
		result.Error = err.Error()
	} else {
		done()
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Success = result.Error == ""

	printReport(result)
	return result, nil
}

// countLines counts non-empty lines in a string.
func countLines(s string) int {
	if s == "" {
		return 0
	}
	return len(strings.Split(strings.TrimSpace(s), "\n"))
}

// stripDockerHeader removes the 8-byte Docker log multiplexing header.
func stripDockerHeader(line string) string {
	if len(line) > 8 {
		// Docker log frames start with [stream_type, 0, 0, 0, size1, size2, size3, size4]
		// If the first byte is 1 (stdout) or 2 (stderr), strip the header
		if line[0] == 1 || line[0] == 2 || line[0] == 0 {
			return line[8:]
		}
	}
	return line
}
