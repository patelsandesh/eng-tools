
static inline int get_current_bucket(){
	uint64_t now = bpf_ktime_get_ns();
	return now/BUCKET_DURATION_NS;
}

static inline int persist_data(uint64_t epoch_now){
	uint32_t epoch_key = EPOCH;
	uint32_t bytest_sent_key = BYTES_SENT;

	bpf_map_update_elem(&UR, &epoch, &epoch_stamp);
	bpf_map_update_elem(&R1, &epoch, &epoch_stamp);
}

static inline int shape(uint64_t duration){
	uint32_t last_bytes_index = LAST_BYTES;
	uint32_t curent_bytes_index = BYTES_SENT;
	uint64_t r0_usage = 0;
	uint64_t *r0_last_bytes = bpf_map_lookup_elem(&R0, &index);
	if (r0_last_bytes) 
	{
		uint64_t r0_curr = bpf_map_lookup_elem(&R0, &curent_bytes_index);
		if (r0_curr){
			r0_usage = *r0_last_bytes - *r0_curr;
		}
	}

	uint64_t r1_usage = 0;
	uint64_t *r1_last_bytes = bpf_map_lookup_elem(&R1, &index);
	if (r1_last_bytes) 
	{
		uint64_t r1_curr = bpf_map_lookup_elem(&R1, &curent_bytes_index);
		if (r1_curr){
			r1_usage = *r1_last_bytes - *r1_curr;
		}
	}

	uint64_t r0_bw = r0_usage / duration;
	uint64_t r1_bw = r1_usage / duration;


}

static inline void try_shape(struct __sk_buff *skb, int class){
	uint64_t current_bucket = get_current_bucket();
	uint32_t index = 1;
	uint32_t *last_epoch = bpf_map_lookup_elem(&gstate, &index);
	if (!last_epoch){
		retrun;
	}
	if (last_epoch < current_bucket ) {
		index = 0;
		uint32_t *lock = bpf_map_lookup_elem(@gstate, &index);
		if (__sync_fetch_and_add(lock, 1)){
			return;
		}
		else{
			last_epoch = bpf_map_lookup_elem(&gstate, &index);
			if (!last_epoch){
				return;
			}
			if (last_epoch < current_bucket ){
				shape(current_bucket - last_epoch);
			}
		}
	}
	return;
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
