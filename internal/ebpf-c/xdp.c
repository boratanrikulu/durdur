#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, long);
	__uint(max_entries, 128);
} drop_to_addrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, long);
	__uint(max_entries, 128);
} drop_from_addrs SEC(".maps");

SEC("xdp_durdur_drop")
int xdp_durdur_drop_func(struct xdp_md* ctx)
{
	void* data_end = (void*)(long)ctx->data_end;
	void* data = (void*)(long)ctx->data;
	struct ethhdr* eth = data;
	long* value;

	uint64_t nh_off = sizeof(*eth);
	if (data + nh_off > data_end) {
		return XDP_PASS;
	}

	struct iphdr* iph = data + nh_off;
	struct udphdr* udph = data + nh_off + sizeof(struct iphdr);
	if (udph + 1 > (struct udphdr*)data_end) {
		return XDP_PASS;
	}

	__u32 ip_drc = iph->daddr;
	value = bpf_map_lookup_elem(&drop_to_addrs, &ip_drc);
	if (value) {
		*value += 1;
		return XDP_DROP;
	}

	__u32 ip_src = iph->saddr;
	value = bpf_map_lookup_elem(&drop_from_addrs, &ip_src);
	if (value) {
		*value += 1;
		return XDP_DROP;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
