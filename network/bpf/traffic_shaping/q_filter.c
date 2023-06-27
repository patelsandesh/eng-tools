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
#define THROTTLE_RATE_BPS (1100 * MB)


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

static inline void update_stats(struct __sk_buff *skb, uint32_t key){
    uint64_t *bytes_sent = bpf_map_lookup_elem(&egress_stats, &key);
	if (bytes_sent)
	{
		__sync_fetch_and_add(bytes_sent, skb->len);
	}

}

static inline int throttle_flow(struct __sk_buff *skb)
{
	// uint64_t bw= R1;
	// uint64_t TH = TIME_HORIZON_NS;
	uint64_t zero = 0;
	uint32_t key = classify(skb);
    
    if (key == 1){
        update_stats(skb, key);
		skb->queue_mapping = 8;
        return TC_ACT_OK;
    }

	uint64_t *last_index = bpf_map_lookup_elem(&rate_map, &key);
	if(!last_index){
		last_index = &zero;
		if (bpf_map_update_elem(&rate_map, &key, &zero, BPF_ANY))
			return TC_ACT_SHOT;
	}
	// uint32_t rand = bpf_get_prandom_u32();
	// uint32_t new_idx = rand % 28;
	// if ((rand % 100) >= 0){
	// 	if (bpf_map_update_elem(&rate_map, &key, &new_idx, BPF_ANY))
	// 		return TC_ACT_SHOT;
	// }
	// skb->queue_mapping = *last_index;
    // update_stats(skb, key);

	uint32_t new_idx = (*last_index + 1 ) % 8;
	__sync_fetch_and_add(last_index, 1);
	bpf_printk("new_idx = %d", new_idx);
	skb->queue_mapping = 3;
    update_stats(skb, key);


	return TC_ACT_OK;
}

__attribute__((section("cls_test"), used)) int tc_prog(struct __sk_buff *skb)
{
	return throttle_flow(skb);
}
char __license[] SEC("license") = "GPL";
