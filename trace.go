package main
import (
"log"
"os"
"os/signal"
"fmt"
"syscall"
"github.com/cilium/ebpf/link"
"github.com/cilium/ebpf/rlimit"
    "path/filepath"
)
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf test test_pid_match.c
func main() {
if err := rlimit.RemoveMemlock(); err != nil { log.Fatal(err) }
var objs testObjects
if err := loadTestObjects(&objs, nil); err != nil { log.Fatal(err) }
defer objs.Close()
tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
if err != nil { log.Fatal(err) }
defer tp.Close()
fmt.Println("Tracing started...")
    
    // Instead of using a ring buffer, test_pid_match.c uses bpf_printk!
    // We can just read from /sys/kernel/tracing/trace_pipe!
stop := make(chan os.Signal, 1)
signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
<-stop
}
