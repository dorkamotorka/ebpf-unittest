#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Size of headers to TCP
#define SIZE (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))

SEC("xdp")
int allow_port_22(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);
    struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);

    if (data + SIZE > data_end) {
        return XDP_DROP;
    }

    // Only allow SSH traffic to pass
    if (ip->protocol == IPPROTO_TCP && tcp->dest == bpf_htons(22)) {
        return XDP_PASS;
    }

    // Drop all other packets
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
