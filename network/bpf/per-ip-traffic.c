#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>

#ifndef __section
           # define __section(x)  __attribute__((section(x), used))
#endif

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2000);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} port_hash_map SEC(".maps");


__attribute__((section("egress"), used))
int drop(struct __sk_buff *skb) {
    const int l3_off = ETH_HLEN;                       // IP header offset
    const int l4_off = l3_off + sizeof(struct iphdr);  // TCP header offset
    const int l7_off = l4_off + sizeof(struct tcphdr); // L7 (e.g. HTTP) header offset
    __u64 *data_len;
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;
    __u64 pkt_size = skb->len;
    __u64 zero = 0;
    if (data_end < data + l7_off)
        return TC_ACT_OK; // Not our packet, handover to kernel

    struct ethhdr *eth = data;
    if (eth->h_proto != htons(ETH_P_IP))
       return TC_ACT_OK; // Not an IPv4 packet, handover to kernel

    struct iphdr *ip = (struct iphdr *)(data + l3_off);
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    // struct tcphdr *tcp = (struct tcphdr *)(data + l4_off);
    __u32 key = ip->saddr;
    data_len = bpf_map_lookup_elem(&port_hash_map, &key);
    if (!data_len){
        bpf_printk("bpf found new IP source %u\n",key);
        data_len = &zero;
    }
    __u64 new_data_len = *data_len + pkt_size;
    bpf_map_update_elem(&port_hash_map, &key, &new_data_len, BPF_ANY);

    return TC_ACT_OK;
}
char __license[] __section("license") = "GPL";

