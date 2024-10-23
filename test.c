#include <bpf/bpf.h>
#include <assert.h>
#include <netinet/ip.h>
#include <linux/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include "allow_ssh.skel.h"

int main(int argc, char *argv[]) {

    // Mock packet data length: Ethernet + IP + TCP
    int pkt_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    char pkt[pkt_len];

    // Fill in Ethernet header
    struct ethhdr *eth_hdr = (struct ethhdr*) pkt;
    unsigned char dest_mac[ETH_ALEN] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB};
    unsigned char src_mac[ETH_ALEN] = {0xAB, 0x89, 0x67, 0x45, 0x23, 0x01};
    memcpy(eth_hdr->h_dest, dest_mac, ETH_ALEN);
    memcpy(eth_hdr->h_source, src_mac, ETH_ALEN);
    eth_hdr->h_proto = htons(ETH_P_IP);

    // Fill in IP header
    struct iphdr *ip_hdr = (struct iphdr*) (pkt + sizeof(struct ethhdr));
    ip_hdr->version = 4;
    ip_hdr->ihl = 5;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = htons(pkt_len);
    ip_hdr->id = htons(42);
    ip_hdr->frag_off = 0;
    ip_hdr->ttl = 64;
    ip_hdr->protocol = IPPROTO_TCP;
    ip_hdr->saddr = inet_addr("192.168.1.1");
    ip_hdr->daddr = inet_addr("192.168.1.2");

    // Fill in TCP header
    struct tcphdr *tcp_hdr = (struct tcphdr*) (pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));
    tcp_hdr->source = htons(12345);  // Arbitrary source port
    tcp_hdr->dest = htons(22);       // Destination port 22 (SSH)
    tcp_hdr->seq = htonl(0);
    tcp_hdr->ack_seq = htonl(0);
    tcp_hdr->doff = 5;
    tcp_hdr->syn = 1;

    // Define BPF_PROG_RUN options with the mock data
    struct bpf_test_run_opts opts = {
        .sz = sizeof(struct bpf_test_run_opts),
        .data_in = pkt,
        .data_size_in = sizeof(pkt),
	.repeat = 1,
    };

    // Load the XDP program
    struct allow_ssh *skel = allow_ssh__open_and_load();
    if (!skel) {
        printf("[error]: failed to open and load program.\n");
        return -1;
    }

    // Get the prog_fd from the skeleton
    int prog_fd = bpf_program__fd(skel->progs.allow_port_22);

    // Run the test with port 22 packet
    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    if (err != 0) {
        printf("[error]: bpf_prog_test_run_opts failed: %d\n", err);
        perror("bpf_prog_test_run_opts");
        return -1;
    }

    // Test result: assert that the packet is allowed (XDP_PASS)
    assert(opts.retval == XDP_PASS);
    printf("[success] packet with destination port 22 passed\n");

    // Modify the TCP header to test for a different port
    tcp_hdr->dest = htons(80);  // Set destination port to 80 (HTTP)

    // Run the test again
    err = bpf_prog_test_run_opts(prog_fd, &opts);
    if (err != 0) {
        printf("[error]: bpf_prog_test_run_opts failed: %d\n", err);
        perror("bpf_prog_test_run_opts");
        return -1;
    }

    // Test result: assert that the packet is dropped (XDP_DROP)
    assert(opts.retval == XDP_DROP);
    printf("[success] packet with destination port 80 dropped\n");

    return 0;
}
