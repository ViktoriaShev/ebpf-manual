#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "better_filter.skel.h"

#define BPF_MAP_PATH_FILTER "/sys/fs/bpf/filter_map"
#define BPF_MAP_PATH_STATS "/sys/fs/bpf/stats_map"

struct filter {
    __be32 ip;
    __be16 port;
};

static void print_usage(const char *prog_name) {
    printf("Usage:\n");
    printf("  %s <ifname> load - attach XDP program to interface\n", prog_name);
    printf("  %s <ifname> unload - detach XDP program from interface\n", prog_name);
    printf("  %s <ifname> add <ip> <port> - add filter rule\n", prog_name);
    printf("  %s <ifname> del <ip> <port> - delete filter rule\n", prog_name);
    printf("  %s <ifname> list - list all filter rules\n", prog_name);
    printf("  %s <ifname> stats - show packet statistics\n", prog_name);
}

static int attach_xdp_program(const char *ifname, struct bpf_program *prog) {
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Failed to get interface index for %s\n", ifname);
        return -1;
    }

    // Явно получаем файловый дескриптор программы
    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program FD: %s\n", strerror(-prog_fd));
        return -1;
    }

    // Используем низкоуровневый API для прикрепления
    int err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(-err));
        return -1;
    }

    printf("XDP program (FD: %d) attached to interface %s\n", prog_fd, ifname);
    return 0;
}


static int add_filter(struct bpf_map *map, const char *ip_str, const char *port_str) {
    struct filter key = {};
    int value = 1;

    if (inet_pton(AF_INET, ip_str, &key.ip) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", ip_str);
        return -1;
    }

    key.port = htons(atoi(port_str));

    int err = bpf_map__update_elem(map, &key, sizeof(key), &value, sizeof(value), BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to add filter: %s\n", strerror(-err));
        return err;
    }

    printf("Added filter: %s:%s %pI4 %d\n", ip_str, port_str, &key.ip,  ntohs(key.port));
    return 0;
}

static int delete_filter(struct bpf_map *map, const char *ip_str, const char *port_str) {
    struct filter key = {};

    if (inet_pton(AF_INET, ip_str, &key.ip) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", ip_str);
        return -1;
    }

    key.port = htons(atoi(port_str));

    int err = bpf_map__delete_elem(map, &key, sizeof(key), 0);
    if (err) {
        fprintf(stderr, "Failed to delete filter: %s\n", strerror(-err));
        return err;
    }

    printf("Deleted filter: %s:%s\n", ip_str, port_str);
    return 0;
}

static int list_filters(struct bpf_map *map) {
    struct filter key = {}, next_key;
    int value, err;

    printf("Current filter rules:\n");

    while (!(err = bpf_map__get_next_key(map, &key, &next_key, sizeof(key)))) {
        if (bpf_map__lookup_elem(map, &next_key, sizeof(next_key), &value, sizeof(value), 0)) {
            fprintf(stderr, "Failed to lookup element: %s\n", strerror(errno));
            return -1;
        }

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &next_key.ip, ip_str, sizeof(ip_str));
        printf("  %s:%d\n", ip_str, ntohs(next_key.port));

        key = next_key;
    }

    if (err != -ENOENT) {
        fprintf(stderr, "Failed to iterate map: %s\n", strerror(-err));
        return -1;
    }

    return 0;
}

static int show_stats(struct better_filter_bpf *skel) {
    struct bpf_map *stats_map = skel->maps.stats_map;
    if (!stats_map) {
        fprintf(stderr, "Stats map not found\n");
        return -1;
    }

    unsigned long long allowed = 0, blocked = 0;
    int zero = 0;

    if (bpf_map__lookup_elem(stats_map, &zero, sizeof(zero), &allowed, sizeof(allowed), 0)) {
        fprintf(stderr, "Failed to read allowed stats: %s\n", strerror(errno));
        return -1;
    }

    zero = 1;
    if (bpf_map__lookup_elem(stats_map, &zero, sizeof(zero), &blocked, sizeof(blocked), 0)) {
        fprintf(stderr, "Failed to read blocked stats: %s\n", strerror(errno));
        return -1;
    }

    printf("Packet statistics:\n");
    printf("  Allowed packets: %llu\n", allowed);
    printf("  Blocked packets: %llu\n", blocked);
    return 0;
}

int main(int argc, char **argv) {
    struct better_filter_bpf *skel = NULL;
    const char *ifname, *cmd;
    int err = 0;

    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    ifname = argv[1];
    cmd = argv[2];

    if (strcmp(cmd, "load") == 0) {
        skel = better_filter_bpf__open_and_load();
        if (!skel) {
            fprintf(stderr, "Failed to open and load BPF skeleton\n");
            return 1;
        }

        err = bpf_map__pin(skel->maps.filter_map, BPF_MAP_PATH_FILTER);
        if (err) {
            fprintf(stderr, "Failed to pin map: %s\n", strerror(-err));
            goto cleanup;
        }

        err = bpf_map__pin(skel->maps.stats_map, BPF_MAP_PATH_STATS);
        if (err) {
            fprintf(stderr, "Failed to pin map: %s\n", strerror(-err));
            goto cleanup;
        }
        err = attach_xdp_program(ifname,skel->progs.xdp_filter);
        if (err) {
            fprintf(stderr, "Failed to attach XDP program: %d\n", err);
            goto cleanup;
        }

        printf("XDP program loaded and attached to %s\n", ifname);
    }
    else if (strcmp(cmd, "unload") == 0) {
        skel = better_filter_bpf__open();
        if (!skel) {
            fprintf(stderr, "Failed to open BPF skeleton\n");
            return 1;
        }

        better_filter_bpf__detach(skel);
        unlink(BPF_MAP_PATH_FILTER);
        printf("XDP program unloaded from %s\n", ifname);
    }
    else {
        skel = better_filter_bpf__open();
        if (!skel) {
            fprintf(stderr, "Failed to open BPF skeleton\n");
            return 1;
        }

        err = better_filter_bpf__load(skel);
        if (err) {
            fprintf(stderr, "Failed to load BPF maps: %d\n", err);
            goto cleanup;
        }

        if (strcmp(cmd, "add") == 0 && argc == 5) {
            err = add_filter(skel->maps.filter_map, argv[3], argv[4]);
        }
        else if (strcmp(cmd, "del") == 0 && argc == 5) {
            err = delete_filter(skel->maps.filter_map, argv[3], argv[4]);
        }
        else if (strcmp(cmd, "list") == 0 && argc == 3) {
            err = list_filters(skel->maps.filter_map);
        }
        else if (strcmp(cmd, "stats") == 0 && argc == 3) {
            err = show_stats(skel);
        }
        else {
            print_usage(argv[0]);
            err = 1;
        }
    }

cleanup:
    if (skel) {
        better_filter_bpf__destroy(skel);
    }
    return err;
}
