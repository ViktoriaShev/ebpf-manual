#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_ICMP 1

struct filter {
    __be32 ip;
    __be16 port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct filter);
    __type(value, int);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} filter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, int);
    __type(value, unsigned long long);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stats_map SEC(".maps");

static bool is_tcp(struct ethhdr *eth, void *data_end)
{

    if ((void *)(eth + 1) > data_end)
        return false;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return false;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return false;

    return ip->protocol == IPPROTO_TCP;
}

static void update_stats(int key, unsigned long long increment)
{
    unsigned long long *count = bpf_map_lookup_elem(&stats_map, &key);
    if (count) {
        __sync_fetch_and_add(count, increment);
    } else {
        unsigned long long init = increment;
        bpf_map_update_elem(&stats_map, &key, &init, BPF_ANY);
    }
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (!is_tcp(eth, data_end))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(*ip) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (struct tcphdr *)((char *)ip + ip_hdr_len);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if ((void *)tcp + 14 > data_end)
    return XDP_PASS;

    __u8 tcp_flags = *((__u8 *)tcp + 13);

    if ((tcp_flags & 0x12) != 0x12) {
        bpf_printk("Not SYN+ACK. flags=0x%x", tcp_flags);
        return XDP_PASS;
    }


    struct filter key = {};
    key.ip = ip->saddr;
    key.port = tcp->source;
    bpf_printk("Trying filter: %pI4:%d\n", &key.ip, bpf_ntohs(key.port));

    int *exists = bpf_map_lookup_elem(&filter_map, &key);
    bpf_printk("Map lookup result: %d", exists);

    if (exists != NULL) {
        update_stats(1, 1);
        bpf_printk("Blocked TCP SYN: %pI4:%d", &key.ip, bpf_ntohs(key.port));
        return XDP_DROP;
    }

    update_stats(0, 1);
    bpf_printk("Passed TCP SYN: %pI4:%d\n", &key.ip, bpf_ntohs(key.port));
    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";