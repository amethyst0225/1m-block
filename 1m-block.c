#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <string.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <time.h>
#include <ctype.h>

#define HASH_TABLE_SIZE 1000003

typedef struct HashNode {
    char *host;
    struct HashNode *next;
} HashNode;

HashNode *hash_table[HASH_TABLE_SIZE];

unsigned int hash(const char *str) {
    unsigned int hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + *str++;
    }
    return hash % HASH_TABLE_SIZE;
}

void insert_blocklist(const char *host) {
    unsigned int index = hash(host);
    HashNode *new_node = (HashNode *)malloc(sizeof(HashNode));
    new_node->host = strdup(host);
    new_node->next = hash_table[index];
    hash_table[index] = new_node;
}

int is_blocked(const char *host) {
    unsigned int index = hash(host);
    HashNode *node = hash_table[index];
    while (node) {
        if (strcasecmp(node->host, host) == 0) {
            return 1;
        }
        node = node->next;
    }
    return 0;
}

void load_blocklist(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open blocklist file");
        exit(EXIT_FAILURE);
    }

    char line[256];
    clock_t start = clock();
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = '\0';  // 개행 제거

        // 콤마 다음 문자열만 추출
        char *dom = strchr(line, ',');
        if (dom) {
            dom++;  // comma 다음으로 이동
            insert_blocklist(dom);
        } else {
            insert_blocklist(line);  // fallback
        }
    }
    clock_t end = clock();
    fclose(file);
    printf("Blocklist loaded in %.2f seconds\n", (double)(end - start) / CLOCKS_PER_SEC);
}



void free_blocklist() {
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        HashNode *node = hash_table[i];
        while (node) {
            HashNode *temp = node;
            node = node->next;
            free(temp->host);
            free(temp);
        }
    }
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    printf(">>> Packet received\n");
    uint32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) id = ntohl(ph->packet_id);

    unsigned char *pkt_data;
    int len = nfq_get_payload(nfa, &pkt_data);
    if (len >= 0) {
        struct iphdr *ip = (struct iphdr *)pkt_data;
        if (ip->protocol == IPPROTO_TCP) {
            int ip_hdr_len = ip->ihl * 4;
            struct tcphdr *tcp = (struct tcphdr *)(pkt_data + ip_hdr_len);
            int tcp_hdr_len = tcp->doff * 4;
            unsigned char *http = pkt_data + ip_hdr_len + tcp_hdr_len;
            int http_len = len - ip_hdr_len - tcp_hdr_len;

            if (http_len > 0) {
                char *h = strcasestr((char *)http, "Host:");
                if (h) {
                    h += 5;
                    while (*h == ' ') h++;
                    char *e = strstr(h, "\r\n");
                    int l = e ? (e - h) : strcspn(h, "\r\n");
                    char host[256];
                    snprintf(host, sizeof(host), "%.*s", l, h);

                    if (strncmp(host, "www.", 4) == 0)
                        memmove(host, host + 4, strlen(host + 4) + 1);

                    printf("Extracted Host: %s\n", host);

                    if (is_blocked(host)) {
                        printf("Dropping packet to blocked host: %s\n", host);
                        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                    }
                } else {
                    printf("Host header not found\n");
                }
            } else {
                printf("No HTTP payload\n");
            }
        }
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd, rv;
    uint32_t queue = 0;
    char buf[4096] __attribute__((aligned));

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <blocklist_file> <queue>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    const char *blocklist_file = argv[1];
    queue = atoi(argv[2]);
    if (queue > 65535) {
        fprintf(stderr, "Queue number must be 0-65535\n");
        exit(EXIT_FAILURE);
    }

    load_blocklist(blocklist_file);

    h = nfq_open();
    if (!h) { perror("nfq_open"); exit(1); }
    if (nfq_unbind_pf(h, AF_INET) < 0) { perror("nfq_unbind_pf"); }
    if (nfq_bind_pf(h, AF_INET) < 0) { perror("nfq_bind_pf"); exit(1); }

    qh = nfq_create_queue(h, queue, &cb, NULL);
    if (!qh) { perror("nfq_create_queue"); exit(1); }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("nfq_set_mode"); exit(1);
    }

    fd = nfq_fd(h);
    printf("[+] Waiting for packets on queue %d...\n", queue);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }
    if (rv < 0 && errno != ENOBUFS) {
        perror("recv failed");
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    free_blocklist();
    return 0;
}