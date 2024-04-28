/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include "tokens.h"

#define NSEC_PER_SEC 1000000000

/* Notice how this XDP/BPF-program contains several programs in the same source
 * file. These will each get their own section in the ELF file, and via libbpf
 * they can be selected individually, and via their file-descriptor attached to
 * a given kernel BPF-hook.
 *
 * The libbpf bpf_object__find_program_by_title() refers to SEC names below.
 * The iproute2 utility also use section name.
 *
 * Slightly confusing, the names that gets listed by "bpftool prog" are the
 * C-function names (below the SEC define).
 */


struct parser_pos {
	void *pos;
};


struct token_params {
    __u64 last_refill_time;
    __u64 no_of_tokens;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16); // TCP or UDP destination port
    __type(value, struct token_params);
    __uint(max_entries, MAX_NUM_FLOWS);
} token_map SEC(".maps");


static __always_inline int parse_eth_hdr(struct parser_pos *parse_pos,
					void *data_end,
					struct ethhdr **eth_hdr)
{
	struct ethhdr * curr_eth_hdr = parse_pos->pos;
	int hdr_size = sizeof(*curr_eth_hdr);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (parse_pos->pos + hdr_size > data_end)
		return -1;

	parse_pos->pos += hdr_size;
	*eth_hdr = curr_eth_hdr;

	return curr_eth_hdr->h_proto; /* network-byte-order */
}

static __always_inline int parse_ip_hdr(struct parser_pos *parse_pos,
					void *data_end,
					struct iphdr **ip_hdr)
{
	struct iphdr * curr_ip_hdr = parse_pos->pos;

    if (curr_ip_hdr + 1 > data_end)
		return -1;

	int ip_hdr_size;
    ip_hdr_size = curr_ip_hdr->ihl * 4;

    if(ip_hdr_size < sizeof(*curr_ip_hdr))
		return -1;

    if (parse_pos->pos + ip_hdr_size > data_end)
		return -1;

    parse_pos->pos += ip_hdr_size;
    *ip_hdr = curr_ip_hdr;

    return curr_ip_hdr->protocol;
}

static __always_inline int parse_ipv6_hdr(struct parser_pos *parse_pos,
                                        void *data_end,
                                        struct ipv6hdr **ipv6_hdr)
{
    struct ipv6hdr *curr_ipv6_hdr = parse_pos->pos;
    // int hdr_size = sizeof(*curr_ipv6_hdr);

    /* Byte-count bounds check; check if current pointer + size of header
     * is after data_end.
     */
    if (curr_ipv6_hdr + 1 > data_end)
        return -1;

    parse_pos->pos = curr_ipv6_hdr + 1;
    *ipv6_hdr = curr_ipv6_hdr;

    return curr_ipv6_hdr->nexthdr;
}

static __always_inline int parse_udp_hdr(struct parser_pos *parse_pos,
                                        void *data_end,
                                        struct udphdr **udp_hdr)
{
    struct udphdr *curr_udp_hdr = parse_pos->pos;
    int size;

    if (curr_udp_hdr + 1 > data_end)
        return -1;

    parse_pos->pos = curr_udp_hdr + 1;
    *udp_hdr = curr_udp_hdr;

    size = bpf_ntohs(curr_udp_hdr->len) - sizeof(struct udphdr);
	if (size < 0)
		return -1;

	return size;
}

static __always_inline int parse_tcp_hdr(struct parser_pos *parse_pos,
                                        void *data_end,
                                        struct tcphdr **tcp_hdr)
{
    struct tcphdr *curr_tcp_hdr = parse_pos->pos;
    int size;

    if (curr_tcp_hdr + 1 > data_end)
        return -1;
    
    size = curr_tcp_hdr->doff * 4;

    if(size < sizeof(*curr_tcp_hdr))
        return -1;

    if(parse_pos->pos + size > data_end)
        return -1;

    parse_pos->pos += size;
    *tcp_hdr = curr_tcp_hdr;

    return size;
}

static __always_inline int parse_icmp_hdr(struct parser_pos *parse_pos,
                                        void *data_end,
                                        struct icmphdr **icmp_hdr)
{
    struct icmphdr *curr_icmp_hdr = parse_pos->pos;
    // int hdr_size = sizeof(*curr_icmp_hdr);

    if (curr_icmp_hdr + 1 > data_end)
        return -1;

    parse_pos->pos = curr_icmp_hdr + 1;
    *icmp_hdr = curr_icmp_hdr;

    return curr_icmp_hdr->type;
}

static __always_inline int parse_icmp6_hdr(struct parser_pos *parse_pos,
                                        void *data_end,
                                        struct icmp6hdr **icmp6_hdr)
{
    struct icmp6hdr *curr_icmp6_hdr = parse_pos->pos;
    // int hdr_size = sizeof(*curr_icmp_hdr);

    if (curr_icmp6_hdr + 1 > data_end)
        return -1;

    parse_pos->pos = curr_icmp6_hdr + 1;
    *icmp6_hdr = curr_icmp6_hdr;

    return curr_icmp6_hdr->icmp6_type;
}



static __always_inline int token_policer(__u16 * dport) {
    // to be done

    bpf_printk("in token func, port no: %d\n", *dport);
    // Lookup token bucket state from map
    struct token_params *bucket_state = bpf_map_lookup_elem(&token_map, dport);

    // Apply token bucket policy
    if (bucket_state) {
        bpf_printk("inside the if key exists area\n");
        // Existing flow - calculate refills and update state
        __u64 current_time = bpf_ktime_get_ns();
        bpf_printk("current time %llu \n", current_time);
        __u64 delta_ns = current_time - bucket_state->last_refill_time;
        __u64 delta_ns_in_sec = delta_ns / NSEC_PER_SEC;
        __u64 num_refills = delta_ns_in_sec * TOKEN_RATE_PPS;

        bpf_printk("refill values: %llu and time: %llu\n", num_refills, delta_ns_in_sec);
        bpf_printk("prev time: %llu, current time: %llu\n", bucket_state->last_refill_time, current_time);
        bpf_printk("no of tokens before : %llu \n", bucket_state->no_of_tokens);
        // Update token count considering refills and potential packet transmission
        // bucket_state->no_of_tokens = bpf_min(bucket_state->no_of_tokens + num_refills, MAX_TOKENS);
        bucket_state->no_of_tokens = (bucket_state->no_of_tokens + num_refills) < MAX_TOKENS ?
                                     (bucket_state->no_of_tokens + num_refills) : MAX_TOKENS;
        
        bpf_printk("no of tokens after refill: %llu \n", bucket_state->no_of_tokens);
        // bucket_state->last_refill_time = current_time;

        if (bucket_state->no_of_tokens > 0) {
            bucket_state->no_of_tokens--;
            bucket_state->last_refill_time = current_time;
            return XDP_TX; // Allow packet
        } 
        else {
            return XDP_DROP; // Drop packet if not enough tokens
        }
    } 
    else {
        bpf_printk("inside the else area\n");
        bpf_printk("max tokens: %u \n", MAX_TOKENS);
        // New flow - allow first packet and initialize state
        struct token_params new_state = {bpf_ktime_get_ns(), MAX_TOKENS-1};
        bpf_printk("no of tokens: %llu, current time: %llu \n", new_state.no_of_tokens, new_state.last_refill_time);
        bpf_map_update_elem(&token_map, dport, &new_state, BPF_ANY);
        return XDP_TX; // Allow first packet
    }

    // return XDP_PASS;
}



SEC("xdp")
int  xdp_pass_func(struct xdp_md *ctx)
{
    bpf_printk("in the first func");
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
    int action = XDP_PASS;

	/* headers parsing*/
	struct ethhdr *eth_hdr;
	struct iphdr *ip_hdr;
	struct ipv6hdr *ipv6_hdr;
	struct udphdr *udp_hdr;
	struct tcphdr *tcp_hdr;
    struct icmphdr *icmp_hdr;
    struct icmp6hdr *icmp6_hdr;

	struct parser_pos parse_pos;
	// int nexthead_type;
	int eth_type, ip_type;
	parse_pos.pos = data;
    __u16 dport;

	/* ethernet header*/
	eth_type = parse_eth_hdr(&parse_pos, data_end, &eth_hdr);

	if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

    bpf_printk("after parsing eth");

	/* ip headers*/
	if(eth_type == bpf_htons(ETH_P_IP)) {

		ip_type = parse_ip_hdr(&parse_pos, data_end, &ip_hdr);
        if (ip_type < 0) {
            action = XDP_ABORTED;
            goto out;
        }

        bpf_printk("after parsing ip4");

        if (ip_type == IPPROTO_UDP) {
            if (parse_udp_hdr(&parse_pos, data_end, &udp_hdr) < 0) {
                action = XDP_DROP;
                goto out;
            }
            else{
                bpf_printk("after parsing udp");
                dport = bpf_ntohs(udp_hdr->dest);
                action = token_policer(&dport);
            }
	    } 
        else if (ip_type == IPPROTO_TCP) {
            if (parse_tcp_hdr(&parse_pos, data_end, &tcp_hdr) < 0) {
                action = XDP_DROP;
                goto out;
            }
            else{
                bpf_printk("after parsing tcp");
                dport = bpf_ntohs(tcp_hdr->dest);
                action = token_policer(&dport);
            }
	    }
        else if (ip_type == IPPROTO_ICMP) {
            if (parse_icmp_hdr(&parse_pos, data_end, &icmp_hdr) < 0) {
                action = XDP_DROP;
                goto out;
            }
            bpf_printk("after parsing icmp");
        } 
        else {
            action = XDP_DROP;
            goto out;
        }
	} 
	else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ipv6_hdr(&parse_pos, data_end, &ipv6_hdr);

        if (ip_type < 0) {
            action = XDP_DROP;
            goto out;
        }

        bpf_printk("after parsing ip6");

        if (ip_type == IPPROTO_UDP) {
            if (parse_udp_hdr(&parse_pos, data_end, &udp_hdr) < 0) {
                action = XDP_DROP;
                goto out;
            }
            else{
                bpf_printk("after parsing udp");
                dport = bpf_ntohs(udp_hdr->dest);
                // __u64 host_port = bpf_ntohs(udp_hdr->dest);
                bpf_printk("port no udp: %d\n", dport);
                action = token_policer(&dport);
            }
	    } 
        else if (ip_type == IPPROTO_TCP) {
            if (parse_tcp_hdr(&parse_pos, data_end, &tcp_hdr) < 0) {
                action = XDP_DROP;
                goto out;
            }
            else{
                bpf_printk("after parsing tcp");
                dport = bpf_ntohs(tcp_hdr->dest);
                action = token_policer(&dport);
            }
	    }
        else if (ip_type == IPPROTO_ICMPV6) {
            if (parse_icmp6_hdr(&parse_pos, data_end, &icmp6_hdr) < 0) {
                action = XDP_DROP;
                goto out;
            }
             bpf_printk("after parsing icmp6");
        } 
        else {
            action = XDP_DROP;
            goto out;
        }
	} 
	else {
        action = XDP_DROP;
		goto out;
	}

    bpf_printk("before returning action: %d", action);
    return action;

    bpf_printk("after returning action");

out:
    return action;
	/* return XDP_PASS; */
}

SEC("xdp")
int  xdp_drop_func(struct xdp_md *ctx)
{
	return XDP_DROP;
}

/* Assignment#2: Add new XDP program section that use XDP_ABORTED */

char _license[] SEC("license") = "GPL";

/* Hint the avail XDP action return codes are:

enum xdp_action {
        XDP_ABORTED = 0,
        XDP_DROP,
        XDP_PASS,
        XDP_TX,
        XDP_REDIRECT,
};
*/
