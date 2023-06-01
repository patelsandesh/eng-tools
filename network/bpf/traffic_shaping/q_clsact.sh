rm -f /sys/fs/bpf/tc/globals/rate_map
rm -f /sys/fs/bpf/tc/globals/egress_stats
clang -O2 -Wall -g -target bpf -c q_filter.c -o q_filter.o
tc qdisc del dev eth2  clsact 2>&1 >/dev/null
tc qdisc add dev eth2 clsact
tc filter add dev eth2 egress bpf da obj q_filter.o  sec cls_test
clang -g  -o qshaper q_shaper.c -lbpf
