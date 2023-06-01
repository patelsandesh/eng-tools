// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>


/* the maximum delay we are willing to add (drop packets beyond that) */
#define TIME_HORIZON_NS (2000 * 1000 * 1000)
#define NS_PER_SEC 1000000000
#define ECN_HORIZON_NS 5000000
#define THROTTLE_RATE_BPS (1100 * 1000 * 1000)

#ifndef __section
           # define __section(x)  __attribute__((section(x), used))
#endif

/* flow_key => last_tstamp timestamp used */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_map SEC(".maps");

static inline int throttle_flow(struct __sk_buff *skb)
{
	int key = 0;
	uint64_t *last_tstamp = bpf_map_lookup_elem(&flow_map, &key);
	uint64_t delay_ns = ((uint64_t)skb->len) * NS_PER_SEC /
			THROTTLE_RATE_BPS;
	uint64_t now = bpf_ktime_get_ns();
	uint64_t tstamp, next_tstamp = 0;

	if (last_tstamp)
		next_tstamp = *last_tstamp + delay_ns;

	tstamp = skb->tstamp;
	if (tstamp < now)
		tstamp = now;

	/* should we throttle? */
	if (next_tstamp <= tstamp) {
		if (bpf_map_update_elem(&flow_map, &key, &tstamp, BPF_ANY))
			return TC_ACT_SHOT;
		return TC_ACT_OK;
	}

	/* do not queue past the time horizon */
	if (next_tstamp - now >= TIME_HORIZON_NS)
		return TC_ACT_SHOT;

	/* set ecn bit, if needed */
	if (next_tstamp - now >= ECN_HORIZON_NS)
		bpf_skb_ecn_set_ce(skb);

	__sync_fetch_and_add(last_tstamp, 1);
	if (bpf_map_update_elem(&flow_map, &key, &next_tstamp, BPF_EXIST))
		return TC_ACT_SHOT;
	skb->tstamp = next_tstamp;

	return TC_ACT_OK;
}

static inline int handle_tcp(struct __sk_buff *skb, struct tcphdr *tcp)
{
	void *data_end = (void *)(long)skb->data_end;
    // bpf_printk("tcp processing packet \n");
	/* drop malformed packets */
	if ((void *)(tcp + 1) > data_end)
		return TC_ACT_SHOT;

	// if (tcp->dest == htons(9000))
	return throttle_flow(skb);

	return TC_ACT_OK;
}

static inline int handle_ipv4(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct iphdr *iph;
	uint32_t ihl;

	/* drop malformed packets */
	if (data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_SHOT;
	iph = (struct iphdr *)(data + sizeof(struct ethhdr));
	if ((void *)(iph + 1) > data_end)
		return TC_ACT_SHOT;
	ihl = iph->ihl * 4;
	if (((void *)iph) + ihl > data_end)
		return TC_ACT_SHOT;

	if (iph->protocol == IPPROTO_TCP)
		return handle_tcp(skb, (struct tcphdr *)(((void *)iph) + ihl));

	return TC_ACT_OK;
}

__attribute__((section("cls_test"), used))
int tc_prog(struct __sk_buff *skb)
{
	if (skb->protocol == htons(ETH_P_IP))
		return handle_ipv4(skb);
    // bpf_printk("bpf found non ip packet \n");
	return TC_ACT_OK;
}
char __license[] SEC("license") = "GPL";