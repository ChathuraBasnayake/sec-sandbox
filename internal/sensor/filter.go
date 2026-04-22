package sensor

import (
	"fmt"
	"os"
	"strings"
)

// IsContainerProcess checks if a given PID belongs to a Docker container
// by inspecting its cgroup file. This is a secondary safety filter on the
// Go side — the primary filtering happens in the BPF probe itself.
func IsContainerProcess(pid int) (bool, string) {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return false, ""
	}

	content := string(data)

	// Docker containers have cgroup entries containing "docker" or "containerd"
	// e.g., "0::/system.slice/docker-<container-id>.scope"
	for _, line := range strings.Split(content, "\n") {
		if strings.Contains(line, "docker") || strings.Contains(line, "containerd") {
			// Extract container ID from the cgroup path
			containerID := extractContainerID(line)
			return true, containerID
		}
	}

	return false, ""
}

// GetContainerIDForPID returns the Docker container ID that a process belongs to.
// Returns empty string if the process is not in a container.
func GetContainerIDForPID(pid int) string {
	isContainer, containerID := IsContainerProcess(pid)
	if !isContainer {
		return ""
	}
	return containerID
}

// extractContainerID pulls the container ID from a cgroup path.
// Handles formats like:
//   - "0::/system.slice/docker-<64-char-hex>.scope"
//   - "0::/docker/<64-char-hex>"
func extractContainerID(cgroupLine string) string {
	// Look for "docker-" prefix (systemd cgroup driver)
	if idx := strings.Index(cgroupLine, "docker-"); idx != -1 {
		id := cgroupLine[idx+7:]
		if dotIdx := strings.Index(id, "."); dotIdx != -1 {
			id = id[:dotIdx]
		}
		if len(id) >= 12 {
			return id[:12] // Short container ID
		}
	}

	// Look for "/docker/" prefix (cgroupfs driver)
	if idx := strings.Index(cgroupLine, "/docker/"); idx != -1 {
		id := cgroupLine[idx+8:]
		if len(id) >= 12 {
			return id[:12]
		}
	}

	// Look for "/containerd/" prefix
	if idx := strings.Index(cgroupLine, "/containerd/"); idx != -1 {
		id := cgroupLine[idx+12:]
		if len(id) >= 12 {
			return id[:12]
		}
	}

	return ""
}
