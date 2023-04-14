Files-

- per-ip-traffic.c -- bpf filter to log per IP traffic on a NIC/OVS-port over a period of 10 seconds

- read-bpf-map.c -- userspace program to read map shared by filter per-ip-traffic

Run time environment (optional)
```
    docker run -ti -v /usr/src:/usr/src:ro        -v /lib/modules/:/lib/modules:ro        -v /sys/kernel/debug/:/sys/kernel/debug:rw  -v $PWD:/nutanix       --net=host --pid=host --privileged        fedora:36  /bin/bash
```
Compilation- Done with fedora:36
```
    dnf install -y clang llvm gcc libbpf libbpf-devel libxdp libxdp-devel xdp-tools bpftool iproute-tc glibc-devel.i686
    clang -O2 -Wall -g -target bpf -c per-ip-traffic.c -o per-ip-traffic.o
    clang -o read-bpf-map  read-bpf-map.c -lbpf
```

Usage-

add qdisc to interface: `tc qdisc add dev eth2 clsact`

add filter to qdisc: `tc filter add dev eth2 egress bpf da obj per-ip-traffic.o  sec egress`

read data: `./read-bpf-map`

cleanup: `tc qdisc del dev eth2  clsact 2>&1 >/dev/null`