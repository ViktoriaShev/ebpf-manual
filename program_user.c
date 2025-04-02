#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <sys/stat.h>

#define BPF_MAP_PATH "/sys/fs/bpf/filter_map"

struct filter {
    __be32 ip;
    __be16 port;
};

// Функция для добавления записи в BPF-карту
void add_entry(const char *ip, const char *port) {
    int map_fd = bpf_obj_get(BPF_MAP_PATH);  // Открытие карты
    if (map_fd < 0) {
        perror("Failed to open BPF map");
        return;
    }
    struct stat st;
    if (fstat(map_fd, &st) == 0)
        printf("FD %d is valid and size: %ld bytes\n", map_fd, st.st_size);
    else
        perror("fstat failed");

    struct bpf_map_info info = {};
    __u32 info_len = sizeof(info);
    if (bpf_obj_get_info_by_fd(map_fd, &info, &info_len) == 0) {
    } else {
        perror("bpf_obj_get_info_by_fd failed");
    }
    struct filter key = {};
    // Преобразуем IP в сетевой порядок байтов (big-endian)
    if (inet_pton(AF_INET, ip, &key.ip) != 1) {
        perror("Invalid IP address");
        close(map_fd);
        return;
    }

    // Преобразуем порт в сетевой порядок байтов (big-endian)
    key.port = htons(atoi(port));
    int value = 1;
    printf("Adding entry: IP=%x, Port=%x\n", ntohl(key.ip), ntohs(key.port));  // Печать IP и порта в читаемом виде

    // Добавляем запись в карту
    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) < 0) {
        perror("Failed to add entry");
    } else {
        printf("Added: %s:%s\n", ip, port);
    }

    close(map_fd);
}
// Функция для удаления записи из BPF-карты
void del_entry(const char *ip, const char *port) {
    int map_fd = bpf_obj_get(BPF_MAP_PATH);
    if (map_fd < 0) {
        perror("Failed to open BPF map");
        return;
    }

    struct filter key = {};
    if (inet_pton(AF_INET, ip, &key.ip) != 1) {
        perror("Invalid IP address");
        close(map_fd);
        return;
    }

    key.port = htons(atoi(port));

    if (bpf_map_delete_elem(map_fd, &key) < 0) {
        perror("Failed to delete entry");
    } else {
        printf("Deleted: %s:%s\n", ip, port);
    }
    close(map_fd);
}

// Функция для вывода содержимого карты
void list_entries() {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "bpftool map dump pinned %s", BPF_MAP_PATH);
    system(cmd);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s add/del/list <IP> <PORT>\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "add") == 0 && argc == 4) {
        add_entry(argv[2], argv[3]);
    } else if (strcmp(argv[1], "del") == 0 && argc == 4) {
        del_entry(argv[2], argv[3]);
    } else if (strcmp(argv[1], "list") == 0) {
        list_entries();
    } else {
        printf("Invalid command\n");
        return 1;
    }
    return 0;
}