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
#define TIME_HORIZON_BW_NS (20 * 1000 * 1000)
#define NS_PER_SEC 1000000000
#define ECN_HORIZON_NS 5000000
#define MB (1024 * 1024)
#define THROTTLE_RATE_BPS (800 * MB)


#define R1 (200 * MB)
#define R2 (430 * MB)

/* flow_key => last_tstamp timestamp used */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 100);
	__type(key, __u32);
	__type(value, __u64);
} flow_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 100);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rate_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 100);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_stats SEC(".maps");



static inline int classify(struct __sk_buff *skb){
	__u32 prioid = skb->priority;
	if (prioid == 1){
		// skb->queue_mapping = 0x03000001;
		// skb->priority = 0;
		return 1;
	}

	// skb->queue_mapping = 0x03000002;
	return 0;
}

// static inline int classify(struct __sk_buff *skb){
// 	// struct task_struct *t = (struct task_struct *)bpf_get_current_task();
// 	__u32 classid = bpf_get_cgroup_classid(skb);
// 	if (classid == 2){
// 		return 1;
// 	}
// 	return 0;
// }

static inline int is_tcp(struct __sk_buff *skb){
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

    return 1;
}

static inline void update_stats(struct __sk_buff *skb, uint32_t key){
    uint64_t *bytes_sent = bpf_map_lookup_elem(&egress_stats, &key);
	if (bytes_sent)
	{
		__sync_fetch_and_add(bytes_sent, skb->len);
	}

}

static inline void update_stats_shot(struct __sk_buff *skb, uint32_t key){
    uint64_t *bytes_sent = bpf_map_lookup_elem(&egress_stats, &key);
	if (bytes_sent)
	{
		__sync_fetch_and_add(bytes_sent, skb->len);
	}

}

static inline int throttle_flow(struct __sk_buff *skb)
{
	// uint64_t bw= R1;
	uint64_t TH = TIME_HORIZON_NS;
	uint32_t key = classify(skb);
    
    if (key == 1){
        update_stats(skb, key);
        return TC_ACT_OK;
    }

	uint64_t *last_tstamp = bpf_map_lookup_elem(&flow_map, &key);
	uint64_t delay_ns = ((uint64_t)skb->len) * NS_PER_SEC /
			THROTTLE_RATE_BPS;
	uint64_t now = bpf_ktime_get_ns();
	uint64_t tstamp, next_tstamp = 0;

	if (!last_tstamp){
		if (bpf_map_update_elem(&flow_map, &key, &now, BPF_ANY))
			return TC_ACT_SHOT;
		return TC_ACT_OK;
	}

	if (last_tstamp)
		next_tstamp = *last_tstamp + delay_ns;

	tstamp = skb->tstamp;
	if (tstamp < now)
		tstamp = now;

	/* should we throttle? */
	if (next_tstamp <= tstamp) {
		if (bpf_map_update_elem(&flow_map, &key, &tstamp, BPF_EXIST))
			return TC_ACT_SHOT;
        update_stats(skb, key);
		return TC_ACT_OK;
	}

	/* do not queue past the time horizon */
	if (next_tstamp - now >= TH){
		update_stats_shot(skb, 2);
		return TC_ACT_SHOT;
	}
		
	/* set ecn bit, if needed */
	if (next_tstamp - now >= ECN_HORIZON_NS)
		bpf_skb_ecn_set_ce(skb);

	// if (bpf_map_update_elem(&flow_map, &key, &next_tstamp, BPF_EXIST))
	// 	return TC_ACT_SHOT;
	__sync_fetch_and_add(last_tstamp, delay_ns);
	
	if(is_tcp(skb))
		skb->tstamp = next_tstamp;
    update_stats(skb, key);
	return TC_ACT_OK;
}

__attribute__((section("cls_test"), used)) int tc_prog(struct __sk_buff *skb)
{
	return throttle_flow(skb);
}
char __license[] SEC("license") = "GPL";
