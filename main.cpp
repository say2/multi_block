#include <stdio.h>
#include <stdlib.h>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <linux/tcp.h> // tcphdr
#include <linux/ip.h> // tcphdr
#include <libnet.h>

#include <openssl/md5.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <utility>
#include <map>


#define METHOD_N 6

std :: map <std :: pair <long long, long long> > M;


const char http_method[6][8] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};
unsigned int method_len[6] = {3, 4, 4, 3, 6, 7};
uint8_t host_tree[1000000][16];

void maketree();

int cmp(uint8_t *a, uint8_t *b);

bool hostcmp(uint8_t *hostname_hash);


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph;
    struct pkt_buff *pkt;
    struct libnet_ipv4_hdr *ip_hdr;
    struct libnet_tcp_hdr *tcp_hdr
    int id = 0, payload_len, i, tcp_hdr_len;
    uint8_t *payload;
    uint8_t *tcp_payload;
    char *host, *tmp;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
        //printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
    }

    payload_len = nfq_get_payload(nfa, &payload);

    ip_hdr = (struct libnet_ipv4_hdr *) payload;

    if (ip_hdr->ip_p != IPPROTO_TCP) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    tcp_hdr = (struct libnet_tcp_hdr *) (payload + LIBNET_IPV4_H);

    //pkt = pktb_alloc(AF_INET , payload, payload_len, 0);
    //ip_h = nfq_ip_get_hdr(pkt);
    //nfq_ip_set_transport_header(pkt, ip_h);
    tcp_hdr_len = tcp_hdr->th_off * 4;
    tcp_payload = (uint8_t *) (tcp_hdr + tcp_hdr_len);
    for (i = 0; i < METHOD_N; i++) {
        if (tcp_payload && !memcmp(tcp_payload, http_method[i], method_len[i])) {
            tmp = strstr((char *) tcp_payload, "Host:");
            tmp = tmp + 6;
            if (tmp) {
                unsigned char digest[16];
                char md5Hash[50] = { 0, };

                MD5_CTX context;
                MD5_Init(&context);
                MD5_Update(&context, (char*)host, strlen((char*)host));
                MD5_Final(digest, &context);
                if (hostcmp(digest)) {
                    printf("block %s", host);
                    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                } else
                    break;
            } else
                break;
        };
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    int debug = 0;
    if (debug == 0) {
        puts("making block host hash tree...");
        maketree();
    }
    if (debug == 1) {

    }
    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}


bool hostcmp(uint8_t *hostname_hash) {

    if(M.find(std::pair <long long,long long>(atoll((char*)hostname_hash),atoll((char*)(hostname_hash+8))))!=M.end())
        return 1;
    else
        return 0;

}

void maketree() {
    int f;
    char s[16];
    for (int i = 0;; i++) {
        f = open("./top-1m.csv_hsh", O_RDONLY);
        if (read(f, s, 16) == -1)
            break;
        M.insert(std::pair <long long, long long>(atoll(s), atoll(s+8));
    }
}