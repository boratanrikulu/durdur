#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <string.h>
#include <stdarg.h>

#define MAX_DNS_NAME_LENGTH 128
#define MAX_ENTRIES 1024

// To see debug logs, set "#define DEBUG 1"
// and watch "/sys/kernel/debug/tracing/trace_pipe" file.
#define DEBUG 1
#ifdef DEBUG
#define printk(fmt, ...)                                           \
	({                                                             \
		bpf_trace_printk(fmt, sizeof(fmt), ##__VA_ARGS__); \
	})
#else
#define printk(fmt, ...)  
#endif

struct dnshdr
{
	uint16_t transaction_id;
	uint8_t rd : 1;		 // Recursion desired
	uint8_t tc : 1;		 // Truncated
	uint8_t aa : 1;		 // Authoritive answer
	uint8_t opcode : 4;	 // Opcode
	uint8_t qr : 1;		 // Query/response flag
	uint8_t rcode : 4;	 // Response code
	uint8_t cd : 1;		 // Checking disabled
	uint8_t ad : 1;		 // Authenticated data
	uint8_t z : 1;		 // Z reserved bit
	uint8_t ra : 1;		 // Recursion available
	uint16_t q_count;	 // Number of questions
	uint16_t ans_count;	 // Number of answer RRs
	uint16_t auth_count; // Number of authority RRs
	uint16_t add_count;	 // Number of resource RRs
};

struct dnsquery
{
	char name[MAX_DNS_NAME_LENGTH];
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, long);
	__uint(max_entries, MAX_ENTRIES);
} drop_to_addrs SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, long);
	__uint(max_entries, MAX_ENTRIES);
} drop_from_addrs SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, MAX_DNS_NAME_LENGTH);
	__uint(value_size, sizeof(long));
	__uint(max_entries, MAX_ENTRIES);
} drop_dns SEC(".maps");

static int parse_query(void *data_end, void *query_start, struct dnsquery *q)
{
	void *cursor = query_start;
	memset(&q->name[0], 0, sizeof(q->name));

	__u8 label_cursor = 0;
	for (__u8 i = 0; i < MAX_DNS_NAME_LENGTH; i++, cursor++)
	{
		if (cursor + 1 > data_end)
		{
			return -1; // packet is too short.
		}

		if (*(__u8 *)cursor == 0)
		{
			break; // end of domain name.
		}

		if (label_cursor == 0)
		{
			// the cursor is on a label length byte.
			__u8 new_label_length = *(__u8 *)cursor;
			if (cursor + new_label_length > data_end)
			{
				return -1; // packet is too short.
			}
			label_cursor = new_label_length;
			q->name[i] = '.';
			continue;
		}

		label_cursor--;
		char c = *(char *)cursor;
		q->name[i] = c;
	}

	return 1;
}

SEC("xdp_durdur_func")
int xdp_durdur_drop_func(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
	{
		return XDP_PASS;
	}

	struct ethhdr *eth = data;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
	{
		return XDP_PASS;
	}

	struct iphdr *ip = data + sizeof(struct ethhdr);

	__u32 ip_drc = ip->daddr;
	if (bpf_map_lookup_elem(&drop_to_addrs, &ip_drc))
	{
		return XDP_DROP;
	}

	__u32 ip_src = ip->saddr;
	if (bpf_map_lookup_elem(&drop_from_addrs, &ip_src))
	{
		return XDP_DROP;
	}

	if (ip->protocol == IPPROTO_UDP)
	{
		struct udphdr *udp;
		if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
		{
			return XDP_PASS;
		}

		udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
		if (udp->source == bpf_htons(53))
		{
			if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(struct dnshdr) > data_end)
			{
				return XDP_PASS;
			}

			struct dnshdr *dns = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
			if (dns->opcode == 0) // it's dns query.
			{
				void *query_start = (void *)dns + sizeof(struct dnshdr);

				struct dnsquery query;
				if (!parse_query(data_end, query_start, &query))
				{
					return XDP_PASS;
				}

				if (bpf_map_lookup_elem(&drop_dns, &query.name))
				{
					printk("[BLOCK] DNS QUERY TO %s", &query.name);
					return XDP_DROP;
				}
				printk("[ALLOW] DNS QUERY TO %s", &query.name);
			}
		}
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
