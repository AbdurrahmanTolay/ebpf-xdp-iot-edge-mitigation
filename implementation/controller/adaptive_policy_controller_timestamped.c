#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define WINDOW_BUCKETS 10
#define BUCKET_NS 1000000000ULL

#define PROTO_UDP      0
#define PROTO_TCP_SYN  1
#define PROTO_ICMP     2

#define POLICY_PASS 0
#define POLICY_DROP 1

#define UDP_THRESHOLD_PPS      0.6
#define TCP_SYN_THRESHOLD_PPS  0.6
#define ICMP_THRESHOLD_PPS     1.1

struct source_key {
    uint32_t src_ipv4;
    uint8_t protocol_class;
    uint8_t pad1;
    uint16_t pad2;
};

struct bucket {
    uint64_t bucket_id;
    uint64_t packets;
    uint64_t bytes;
};

struct source_window {
    struct bucket buckets[WINDOW_BUCKETS];
};

static volatile sig_atomic_t stop = 0;

static void handle_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static uint64_t monotonic_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static void realtime_timestamp(char *buffer, size_t buffer_size)
{
    struct timespec ts;
    struct tm local_tm;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        snprintf(buffer, buffer_size, "TIMESTAMP_ERROR");
        return;
    }

    if (localtime_r(&ts.tv_sec, &local_tm) == NULL) {
        snprintf(buffer, buffer_size, "TIMESTAMP_ERROR");
        return;
    }

    char date_part[32];
    char zone_part[8] = {0};
    char formatted_zone[8] = {0};

    strftime(date_part, sizeof(date_part), "%Y-%m-%dT%H:%M:%S", &local_tm);
    strftime(zone_part, sizeof(zone_part), "%z", &local_tm);

    if (strlen(zone_part) == 5) {
        formatted_zone[0] = zone_part[0];
        formatted_zone[1] = zone_part[1];
        formatted_zone[2] = zone_part[2];
        formatted_zone[3] = ':';
        formatted_zone[4] = zone_part[3];
        formatted_zone[5] = zone_part[4];
        formatted_zone[6] = '\0';
    } else {
        snprintf(formatted_zone, sizeof(formatted_zone), "Z");
    }

    snprintf(buffer, buffer_size, "%s.%09ld%s", date_part, ts.tv_nsec, formatted_zone);
}

static const char *protocol_name(uint8_t protocol_class)
{
    switch (protocol_class) {
    case PROTO_UDP: return "UDP";
    case PROTO_TCP_SYN: return "TCP_SYN";
    case PROTO_ICMP: return "ICMP";
    default: return "UNKNOWN";
    }
}

static double threshold_for_protocol(uint8_t protocol_class)
{
    switch (protocol_class) {
    case PROTO_UDP: return UDP_THRESHOLD_PPS;
    case PROTO_TCP_SYN: return TCP_SYN_THRESHOLD_PPS;
    case PROTO_ICMP: return ICMP_THRESHOLD_PPS;
    default: return -1.0;
    }
}

static int find_map_fd_by_name(const char *target_name)
{
    uint32_t id = 0;
    uint32_t next_id;

    while (bpf_map_get_next_id(id, &next_id) == 0) {
        int fd = bpf_map_get_fd_by_id(next_id);

        if (fd >= 0) {
            struct bpf_map_info info;
            uint32_t info_len = sizeof(info);
            memset(&info, 0, sizeof(info));

            if (bpf_obj_get_info_by_fd(fd, &info, &info_len) == 0) {
                if (strncmp((const char *)info.name, target_name, BPF_OBJ_NAME_LEN) == 0)
                    return fd;
            }

            close(fd);
        }

        id = next_id;
    }

    return -1;
}

static uint64_t window_packet_count(
    int source_map_fd,
    struct source_key *key,
    unsigned char *values,
    int possible_cpus,
    size_t per_cpu_stride)
{
    uint64_t current_bucket = monotonic_ns() / BUCKET_NS;
    size_t values_size = per_cpu_stride * (size_t)possible_cpus;

    memset(values, 0, values_size);

    if (bpf_map_lookup_elem(source_map_fd, key, values) != 0) {
        if (errno == ENOENT)
            return 0;
        perror("bpf_map_lookup_elem");
        return 0;
    }

    uint64_t total_packets = 0;

    for (int cpu = 0; cpu < possible_cpus; cpu++) {
        struct source_window *window =
            (struct source_window *)(values + ((size_t)cpu * per_cpu_stride));

        for (int slot = 0; slot < WINDOW_BUCKETS; slot++) {
            struct bucket *b = &window->buckets[slot];

            if (b->bucket_id == 0)
                continue;
            if (b->bucket_id > current_bucket)
                continue;
            if ((current_bucket - b->bucket_id) >= WINDOW_BUCKETS)
                continue;

            total_packets += b->packets;
        }
    }

    return total_packets;
}

static int set_drop_policy(int policy_map_fd, struct source_key *key)
{
    uint32_t action = POLICY_DROP;
    return bpf_map_update_elem(policy_map_fd, key, &action, BPF_ANY);
}

static int clear_policy(int policy_map_fd, struct source_key *key)
{
    int ret = bpf_map_delete_elem(policy_map_fd, key);
    if (ret != 0 && errno != ENOENT)
        return -1;
    return 0;
}

static void clear_profile_policies(int policy_map_fd, uint32_t profile_ip)
{
    for (uint8_t proto = 0; proto <= 2; proto++) {
        struct source_key key = {};
        key.src_ipv4 = profile_ip;
        key.protocol_class = proto;
        clear_policy(policy_map_fd, &key);
    }
}

int main(int argc, char **argv)
{
    const char *profile_ip_string = "192.168.1.100";
    unsigned int interval_seconds = 1;
    int enforce = 0;

    if (argc >= 2)
        profile_ip_string = argv[1];

    if (argc >= 3) {
        interval_seconds = (unsigned int)strtoul(argv[2], NULL, 10);
        if (interval_seconds == 0)
            interval_seconds = 1;
    }

    if (argc >= 4 && strcmp(argv[3], "--enforce") == 0)
        enforce = 1;

    uint32_t profile_ip;

    if (inet_pton(AF_INET, profile_ip_string, &profile_ip) != 1) {
        fprintf(stderr, "Invalid IPv4 address: %s\n", profile_ip_string);
        return EXIT_FAILURE;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    int possible_cpus = libbpf_num_possible_cpus();

    if (possible_cpus <= 0) {
        fprintf(stderr, "Unable to determine possible CPU count\n");
        return EXIT_FAILURE;
    }

    size_t value_size = sizeof(struct source_window);
    size_t per_cpu_stride = (value_size + 7) & ~((size_t)7);
    size_t values_size = per_cpu_stride * (size_t)possible_cpus;

    unsigned char *values = calloc(1, values_size);

    if (!values) {
        perror("calloc");
        return EXIT_FAILURE;
    }

    int source_map_fd = find_map_fd_by_name("source_rings");

    if (source_map_fd < 0) {
        fprintf(stderr, "Could not find map: source_rings\n");
        free(values);
        return EXIT_FAILURE;
    }

    int policy_map_fd = find_map_fd_by_name("mitig_policy");

    if (policy_map_fd < 0) {
        fprintf(stderr, "Could not find map: mitig_policy\n");
        fprintf(stderr, "Attach xdp_policy_mitigation.o first.\n");
        close(source_map_fd);
        free(values);
        return EXIT_FAILURE;
    }

    clear_profile_policies(policy_map_fd, profile_ip);

    char startup_timestamp[96];
    realtime_timestamp(startup_timestamp, sizeof(startup_timestamp));

    printf("\n");
    printf("Stage 5I-B — Adaptive Policy Controller\n");
    printf("=======================================\n");
    printf("Started          : %s\n", startup_timestamp);
    printf("Profiled source  : %s\n", profile_ip_string);
    printf("Window           : %d seconds\n", WINDOW_BUCKETS);
    printf("Interval         : %u second(s)\n", interval_seconds);
    printf("Mode             : %s\n", enforce ? "ENFORCE" : "DRY-RUN");
    printf("\n");
    printf("UDP threshold      : %.2f PPS\n", UDP_THRESHOLD_PPS);
    printf("TCP_SYN threshold  : %.2f PPS\n", TCP_SYN_THRESHOLD_PPS);
    printf("ICMP threshold     : %.2f PPS\n", ICMP_THRESHOLD_PPS);
    printf("\n");

    if (!enforce)
        printf("DRY-RUN: policy map will NOT be changed.\n");
    else
        printf("ENFORCE: ALERT states install XDP_DROP policies.\n");

    printf("Ctrl+C clears this profile's policies and exits.\n\n");

    setvbuf(stdout, NULL, _IOLBF, 0);

    while (!stop) {
        printf("%-35s %-15s %-9s %9s %10s %-8s %-10s %10s\n",
               "TIMESTAMP", "SOURCE", "CLASS", "PPS", "THRESHOLD",
               "DETECT", "POLICY", "PKTS/10s");

        printf("----------------------------------------------------------------------------------------------------------\n");

        for (uint8_t proto = 0; proto <= 2; proto++) {
            struct source_key key = {};
            key.src_ipv4 = profile_ip;
            key.protocol_class = proto;

            uint64_t packets = window_packet_count(
                source_map_fd, &key, values, possible_cpus, per_cpu_stride);

            double pps = (double)packets / (double)WINDOW_BUCKETS;
            double threshold = threshold_for_protocol(proto);
            int alert = (pps > threshold);

            const char *detect_status = alert ? "ALERT" : "NORMAL";
            const char *policy_status = "PASS";

            if (enforce) {
                if (alert) {
                    if (set_drop_policy(policy_map_fd, &key) != 0) {
                        perror("set_drop_policy");
                        policy_status = "ERROR";
                    } else {
                        policy_status = "DROP";
                    }
                } else {
                    if (clear_policy(policy_map_fd, &key) != 0) {
                        perror("clear_policy");
                        policy_status = "ERROR";
                    } else {
                        policy_status = "PASS";
                    }
                }
            } else {
                policy_status = alert ? "WOULD_DROP" : "PASS";
            }

            char sample_timestamp[96];
            realtime_timestamp(sample_timestamp, sizeof(sample_timestamp));

            printf("%-35s %-15s %-9s %9.3f %10.3f %-8s %-10s %10llu\n",
                   sample_timestamp,
                   profile_ip_string,
                   protocol_name(proto),
                   pps,
                   threshold,
                   detect_status,
                   policy_status,
                   (unsigned long long)packets);
        }

        printf("\n");

        for (unsigned int i = 0; i < interval_seconds && !stop; i++)
            sleep(1);
    }

    char shutdown_timestamp[96];
    realtime_timestamp(shutdown_timestamp, sizeof(shutdown_timestamp));

    printf("\n%s Clearing mitigation policies for %s...\n",
           shutdown_timestamp, profile_ip_string);

    clear_profile_policies(policy_map_fd, profile_ip);

    realtime_timestamp(shutdown_timestamp, sizeof(shutdown_timestamp));
    printf("%s Policies cleared. Controller stopped.\n", shutdown_timestamp);

    close(policy_map_fd);
    close(source_map_fd);
    free(values);

    return EXIT_SUCCESS;
}
