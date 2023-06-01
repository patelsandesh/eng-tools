// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <linux/sched.h>


/* the maximum delay we are willing to add (drop packets beyond that) */
#define TIME_HORIZON_NS (2000 * 1000 * 1000)
#define NS_PER_SEC 1000000000
#define ECN_HORIZON_NS 5000000
#define THROTTLE_RATE_BPS (90 * 1000 * 1000)


/* flow_key => last_tstamp timestamp used */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 100);
    __type(key, __u32);
    __type(value, __u64);
} qidx_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 100);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rate_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 100);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_stats SEC(".maps");

// static inline int classify(struct __sk_buff *skb){
// 	// struct task_struct *t = (struct task_struct *)bpf_get_current_task();
// 	__u32 classid = bpf_get_cgroup_classid(skb);
// 	if (classid == 65539){
// 		return 1;
// 	}
// 	return 0;
// }

static inline int classify(struct __sk_buff *skb){
	const int l3_off = ETH_HLEN;                       // IP header offset
    const int l4_off = l3_off + sizeof(struct iphdr);  // TCP header offset
    const int l7_off = l4_off + sizeof(struct tcphdr); // L7 (e.g. HTTP) header offset
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    if (data_end < data + l7_off)
        return 0; // Not our packet, handover to kernel

    struct ethhdr *eth = data;
    if (eth->h_proto != htons(ETH_P_IP))
       return 0; // Not an IPv4 packet, handover to kernel

    struct iphdr *ip = (struct iphdr *)(data + l3_off);
    if (ip->protocol != IPPROTO_TCP)
        return 0;

    // struct tcphdr *tcp = (struct tcphdr *)(data + l4_off);
    __u32 key = ip->saddr;
    __u32 target_ip = htonl(0x0A600455);
	if (key == target_ip){
		return 1;
	}

    return 0;
}

static inline int throttle_flow(struct __sk_buff *skb)
{
	uint32_t key = classify(skb);
    int index = 0;
    uint64_t *base = bpf_map_lookup_elem(&rate_map, &key);
    if (!base){
        return TC_ACT_OK;
    }
    uint32_t count_key = 2*key + 1;
    uint64_t *count = bpf_map_lookup_elem(&rate_map, &count_key);
    if (!count || *count == 0){
        return TC_ACT_OK;
    }
    uint64_t *last_index = bpf_map_lookup_elem(&qidx_map, &key);
    if(!last_index){
        return TC_ACT_OK;
    }
    index = *last_index;
    __sync_fetch_and_add(last_index, 1);
    // queue mapping start from 1
    skb->queue_mapping = (index % *count) + *base + 1;
    uint64_t *bytes_sent = bpf_map_lookup_elem(&egress_stats, &key);
    if (bytes_sent){
        __sync_fetch_and_add(bytes_sent, skb->len);
    }
	// if (key == 1){
	// 	skb->queue_mapping = 0x13;
	// } else {
	// 	skb->queue_mapping = 0x17;
	// }
    // skb->queue_mapping = 0x17;
	return TC_ACT_OK;
}

__attribute__((section("cls_test"), used))
int tc_prog(struct __sk_buff *skb)
{	
	return throttle_flow(skb);
}
char __license[] SEC("license") = "GPL";