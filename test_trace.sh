sudo bpftrace -e 'tracepoint:syscalls:sys_enter_open,tracepoint:syscalls:sys_enter_openat /comm == "sh"/ { printf("OPEN: %s\n", str(args->filename)); }' > trace.out &
BPF_PID=$!
sleep 2
docker rm -f test_marker 2>/dev/null
docker run --rm alpine sh -c 'exec 9> /tmp/DT_INIT; sleep 2'
sudo kill $BPF_PID
cat trace.out | grep DT_INIT
