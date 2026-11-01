#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define WINDOW_BUCKETS 10
#define BUCKET_NS 1000000000ULL

#define PROTO_UDP      0
#define PROTO_TCP_SYN  1
#define PROTO_ICMP     2

#define POLICY_PASS 0
#define POLICY_DROP 1

#define IPV4_PROTO_ICMP 1
#define IPV4_PROTO_TCP  6
#define IPV4_PROTO_UDP  17

#define IPV4_FRAG_MF     0x2000
#define IPV4_FRAG_OFFSET 0x1fff

struct source_key {
    __u32 src_ipv4;
    __u8 protocol_class;
    __u8 pad1;
    __u16 pad2;
};

struct bucket {
    __u64 bucket_id;
    __u64 packets;
    __u64 bytes;
};

struct source_window {
    struct bucket buckets[WINDOW_BUCKETS];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct source_key);
    __type(value, struct source_window);
} source_rings SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct source_key);
    __type(value, __u32);
} mitig_policy SEC(".maps");

static __always_inline struct bucket *
get_bucket(struct source_window *window, __u32 slot)
{
    switch (slot) {
    case 0: return &window->buckets[0];
    case 1: return &window->buckets[1];
    case 2: return &window->buckets[2];
    case 3: return &window->buckets[3];
    case 4: return &window->buckets[4];
    case 5: return &window->buckets[5];
    case 6: return &window->buckets[6];
    case 7: return &window->buckets[7];
    case 8: return &window->buckets[8];
    case 9: return &window->buckets[9];
    default: return 0;
    }
}

static __always_inline void
update_source_window(struct source_key *key, __u64 current_bucket, __u64 packet_bytes)
{
    struct source_window *window = bpf_map_lookup_elem(&source_rings, key);

    if (!window) {
        struct source_window initial = {};
        bpf_map_update_elem(&source_rings, key, &initial, BPF_NOEXIST);
        window = bpf_map_lookup_elem(&source_rings, key);
        if (!window)
            return;
    }

    __u32 slot = (__u32)(current_bucket % WINDOW_BUCKETS);
    struct bucket *bucket = get_bucket(window, slot);

    if (!bucket)
        return;

    if (bucket->bucket_id != current_bucket) {
        bucket->bucket_id = current_bucket;
        bucket->packets = 1;
        bucket->bytes = packet_bytes;
    } else {
        bucket->packets += 1;
        bucket->bytes += packet_bytes;
    }
}

static __always_inline int
policy_action(struct source_key *key)
{
    __u32 *action = bpf_map_lookup_elem(&mitig_policy, key);

    if (!action)
        return POLICY_PASS;

    if (*action == POLICY_DROP)
        return POLICY_DROP;

    return POLICY_PASS;
}

SEC("xdp")
int xdp_source_policy(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);

    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->version != 4)
        return XDP_PASS;

    __u32 ihl_bytes = (__u32)iph->ihl * 4;

    if (ihl_bytes < sizeof(struct iphdr))
        return XDP_PASS;

    if ((void *)iph + ihl_bytes > data_end)
        return XDP_PASS;

    struct source_key key = {};
    key.src_ipv4 = iph->saddr;
    int classified = 0;

    if (iph->protocol == IPV4_PROTO_UDP) {
        key.protocol_class = PROTO_UDP;
        classified = 1;
    } else if (iph->protocol == IPV4_PROTO_ICMP) {
        key.protocol_class = PROTO_ICMP;
        classified = 1;
    } else if (iph->protocol == IPV4_PROTO_TCP) {
        __u16 frag = bpf_ntohs(iph->frag_off);

        if (frag & (IPV4_FRAG_MF | IPV4_FRAG_OFFSET))
            return XDP_PASS;

        struct tcphdr *tcp = (void *)iph + ihl_bytes;

        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        if (tcp->syn && !tcp->ack) {
            key.protocol_class = PROTO_TCP_SYN;
            classified = 1;
        }
    }

    if (!classified)
        return XDP_PASS;

    __u64 now_ns = bpf_ktime_get_ns();
    __u64 current_bucket = now_ns / BUCKET_NS;
    __u64 packet_bytes = (__u64)((long)data_end - (long)data);

    update_source_window(&key, current_bucket, packet_bytes);

    if (policy_action(&key) == POLICY_DROP)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
