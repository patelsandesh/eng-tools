#include <linux/bpf.h>
#include <bpf/bpf.h>
// #include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>

#define SLEEP_TIME 10

int main()
{
    int fd = bpf_obj_get("/sys/fs/bpf/tc/globals/port_hash_map");
    if (fd < 0)
    {
        printf("could not open file\n");
    }
    else
    {
        printf("fd loaded successfully\n");
    }
    __u32 key, next_key;
    __u64 value;
    key = 0;
    next_key = 0;
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0)
    {
        bpf_map_delete_elem(fd, &next_key);
        key = next_key;
    }
    sleep(SLEEP_TIME);
    key = 0;
    next_key = 0;
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0)
    {
        bpf_map_lookup_elem(fd, &next_key, &value);
        struct in_addr ipaddr = {.s_addr = next_key};
        printf("IP: %-20s BW (MBps): %-20llu\n", inet_ntoa(ipaddr), (value >> 20) / SLEEP_TIME);
        key = next_key;
    }
    return 0;
}
