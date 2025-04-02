/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>

#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6

// Структура фильтра (IP + порт)
struct filter {
    __be32 ip;
    __be16 port;
};

// Определение eBPF-карты filter_map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct filter);
    __type(value, int);
} filter_map SEC(".maps");

// XDP программа фильтрации пакетов
SEC("xdp")
int filter_packets(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;
    bpf_printk("Ethernet protocol: %04x, Expected: %04x\n", eth->h_proto, ETH_P_IP);

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    struct filter key = {};
    key.ip = ip->saddr;

    // Определяем порт, в зависимости от протокола
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((unsigned char *)ip + ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        key.port = tcp->source;
    } else if (ip->protocol == IPPROTO_ICMP) {
        key.port = 0; // Для ICMP-пакетов порт всегда 0
    } else {
        return XDP_PASS; // Пропускаем другие протоколы
    }
    // Печать информации о пакете для отладки
    bpf_printk("Packet: IP=%x, Protocol=%d, Port=%d\n", key.ip, ip->protocol, key.port);

    // Проверяем карту фильтров
    int *value = bpf_map_lookup_elem(&filter_map, &key);
    bpf_printk("%d\n",value);
    if (value != NULL) {
        bpf_printk("Blocked packet: source_ip=%x, source_port=%d\n", key.ip, key.port);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

