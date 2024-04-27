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
    u64 last_refill_time;
    u64 no_of_tokens;
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



static __always_inline int xdp_token_policer(__u16 port) {
    // to be done
    return XDP_PASS;
}



SEC("xdp")
int  xdp_pass_func(struct xdp_md *ctx)
{
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

	/* ethernet header*/
	eth_type = parse_eth_hdr(&parse_pos, data_end, &eth_hdr);

	if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

	/* ip headers*/
	if(eth_type == bpf_htons(ETH_P_IP)) {

		ip_type = parse_ip_hdr(&parse_pos, data_end, &ip_hdr);
        if (ip_type < 0) {
            action = XDP_ABORTED;
            goto out;
        }

        if (ip_type == IPPROTO_UDP) {
            if (parse_udp_hdr(&parse_pos, data_end, &udp_hdr) < 0) {
                action = XDP_DROP;
                goto out;
            }
	    } 
        else if (ip_type == IPPROTO_TCP) {
            if (parse_tcp_hdr(&parse_pos, data_end, &tcp_hdr) < 0) {
                action = XDP_DROP;
                goto out;
            }
	    }
        else if (ip_type == IPPROTO_ICMP) {
            if (parse_icmp_hdr(&parse_pos, data_end, &icmp_hdr) < 0) {
                action = XDP_DROP;
                goto out;
            }
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

        if (ip_type == IPPROTO_UDP) {
            if (parse_udp_hdr(&parse_pos, data_end, &udp_hdr) < 0) {
                action = XDP_DROP;
                goto out;
            }
	    } 
        else if (ip_type == IPPROTO_TCP) {
            if (parse_tcp_hdr(&parse_pos, data_end, &tcp_hdr) < 0) {
                action = XDP_DROP;
                goto out;
            }
	    }
        else if (ip_type == IPPROTO_ICMPV6) {
            if (parse_icmp6_hdr(&parse_pos, data_end, &icmp6_hdr) < 0) {
                action = XDP_DROP;
                goto out;
            }
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
