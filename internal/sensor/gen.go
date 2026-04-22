package sensor

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event probe ../../ebpf/probe.c -- -I../../ebpf/headers -I/usr/include/bpf
