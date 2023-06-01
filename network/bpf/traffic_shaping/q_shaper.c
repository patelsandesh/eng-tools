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
#include <stdlib.h>

#define SLEEP_TIME 1
#define NCLASSES 2
#define MB 1024*1024

const char* rate_map = "/sys/fs/bpf/tc/globals/rate_map";
const char* egress_stats_map = "/sys/fs/bpf/tc/globals/egress_stats";

uint64_t reservation[] = {24, 8};
uint64_t BWE = 1175*1024*1024;


int map_open(const char* filepath){
    int fd = bpf_obj_get(filepath);
    if (fd < 0)
    {
        printf("could not bpf map %s\n", filepath);
        exit(1);
    }
    else
    {
        printf("bpf map loaded successfully path: %s\n", filepath);
    }
    return fd;
}

int shaper(){
    uint64_t *temp, *current, *last;
    uint64_t unused = 0, used = 0;
    uint64_t bytes_sent_latest[NCLASSES] = {0};
    uint64_t bytes_sent_last[NCLASSES] = {0};
    uint64_t bw_rate[NCLASSES*2];
    current = &(bytes_sent_latest[0]);
    last = &(bytes_sent_last[0]);
    int rate_fd = map_open(rate_map);
    int stats_fd = map_open(egress_stats_map);
    int base =0, size=0;
    for(int i=0; i<NCLASSES; i++){
        /*
        make sure the array sizes match
        */
        bw_rate[2*i] = base;
        bw_rate[2*i + 1] = reservation[i];
        base += reservation[i];
    }
    for (int i=0; i<2*NCLASSES; i++){
        bpf_map_update_elem(rate_fd, &i, &bw_rate[i], BPF_ANY);
    }
    // read current stats
    uint64_t duration = 1;
    while(1){
        for(int i=0; i<NCLASSES; i++){
            /*
                try other signature to check for errors
            */
            bpf_map_lookup_elem(stats_fd, &i, &(current[i]));
        }

        unused = 0;
        used = 0 ;
        for(int i=0; i<NCLASSES; i++){
            uint64_t bw_i = (current[i] - last[i]) / SLEEP_TIME;
            printf("class %d\tbw mb: %lu\t\t bytes %lu\n", i, bw_i/(MB), current[i]);
        }
        temp = last;
        last = current;
        current = temp;
        sleep(SLEEP_TIME);
    }
    return 0;
}


int main(){
    return shaper();
}