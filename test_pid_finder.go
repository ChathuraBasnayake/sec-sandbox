package main

import (
"fmt"
"os"
"path/filepath"
"strconv"
"strings"
)

func main() {
marker := os.Args[1]
fmt.Printf("Searching for marker: %s\n", marker)

entries, _ := os.ReadDir("/proc")
var targetMntNs string

for _, entry := range entries {
if !entry.IsDir() {
continue
}
pid, err := strconv.ParseUint(entry.Name(), 10, 32)
if err != nil {
continue
}
cmdlinePath := filepath.Join("/proc", entry.Name(), "cmdline")
data, err := os.ReadFile(cmdlinePath)
if err != nil {
continue
}
if strings.Contains(string(data), marker) {
mntPath := filepath.Join("/proc", entry.Name(), "ns", "mnt")
mntNs, _ := os.Readlink(mntPath)
fmt.Printf("MATCH FOUND: PID=%d CMD=%s MNT=%s\n", pid, string(data), mntNs)
targetMntNs = mntNs
break
}
}

if targetMntNs == "" {
fmt.Println("Marker not found.")
return
}

fmt.Printf("Finding all processes with mount namespace: %s\n", targetMntNs)
for _, entry := range entries {
if !entry.IsDir() {
continue
}
pid, err := strconv.ParseUint(entry.Name(), 10, 32)
if err != nil {
continue
}
mntPath := filepath.Join("/proc", entry.Name(), "ns", "mnt")
mntNs, _ := os.Readlink(mntPath)
if mntNs == targetMntNs {
cmdlinePath := filepath.Join("/proc", entry.Name(), "cmdline")
data, _ := os.ReadFile(cmdlinePath)
fmt.Printf("  SIBLING: PID=%d CMD=%s\n", pid, string(data))
}
}
}
