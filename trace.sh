sudo bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("BPF-PID: %d = %s\n", pid, str(args->filename)); }' > trace.out &
BPF_PID=$!
sleep 2

docker rm -f test_pid 2>/dev/null
docker run -d --name test_pid alpine sh -c 'sleep 300'
sleep 2

DOC_PID=$(docker inspect -f '{{.State.Pid}}' test_pid)
echo "Docker Inspect PID for container: $DOC_PID"

docker exec test_pid touch /tmp/hello_from_inside

sudo kill $BPF_PID
cat trace.out | grep touch
