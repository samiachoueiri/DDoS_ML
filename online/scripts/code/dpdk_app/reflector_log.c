/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <stdalign.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <getopt.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_regexdev.h>

#include <rte_crypto.h>
#include <rte_cryptodev.h>

#include <rte_ether.h>
#include <rte_ip.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8192
#define BURST_SIZE 1000

#define MAX_FILE_NAME 255
#define MAX_SERVER_NAME 255
#define MBUF_CACHE_SIZE 256
#define MBUF_SIZE (1 << 8)


struct qps_per_lcore
{
    unsigned int lcore_id;
    int socket;
    uint16_t qp_id_base;
    uint16_t nb_qps;
};



/* >8 End of launching function on lcore. */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf;
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxconf;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    rte_eth_promiscuous_enable(port);

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0)
    {
        printf("Error during getting device (port %u) info: %s\n",
               port, strerror(-retval));

        return retval;
    }

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;
    rxconf = dev_info.default_rxconf;

    for (q = 0; q < rx_rings; q++)
    {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                        rte_eth_dev_socket_id(port), &rxconf, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    for (q = 0; q < tx_rings; q++)
    {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }
    retval = rte_eth_dev_start(port);
    if (retval < 0)
    {
        return retval;
    }
    return 0;
}

#define MAX_PORTS RTE_MAX_ETHPORTS

static volatile bool force_quit = false;
static bool enable_logging = false;

struct port_stats {
    uint64_t rx;
    uint64_t tx;
    uint64_t dropped;
    uint64_t ipv4;
};

static struct port_stats stats[RTE_MAX_LCORE][MAX_PORTS];

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;
    }
}

static void log_packet(uint16_t port,
                        unsigned int lcore_id,
                        struct rte_mbuf *mbuf,
                        struct rte_ether_hdr *eth_hdr,
                        struct rte_ipv4_hdr *ip_hdr,
                        bool is_ipv4) {
    
    char src_mac[RTE_ETHER_ADDR_FMT_SIZE];
    char dst_mac[RTE_ETHER_ADDR_FMT_SIZE];

    rte_ether_format_addr(src_mac, sizeof(src_mac), &eth_hdr->src_addr);
    rte_ether_format_addr(dst_mac, sizeof(dst_mac), &eth_hdr->dst_addr);

    if (is_ipv4 && ip_hdr != NULL) {
        uint32_t src_ip = rte_be_to_cpu_32(ip_hdr->src_addr);
        uint32_t dst_ip = rte_be_to_cpu_32(ip_hdr->dst_addr);

        printf("core=%u port=%u len=%u eth_src=%s eth_dst=%s "
               "ipv4_src=%u.%u.%u.%u ipv4_dst=%u.%u.%u.%u\n",
               lcore_id,
               port,
               rte_pktmbuf_pkt_len(mbuf),
               src_mac,
               dst_mac,
               (src_ip >> 24) & 0xff,
               (src_ip >> 16) & 0xff,
               (src_ip >> 8) & 0xff,
               src_ip & 0xff,
               (dst_ip >> 24) & 0xff,
               (dst_ip >> 16) & 0xff,
               (dst_ip >> 8) & 0xff,
               dst_ip & 0xff);
    } else {
        printf("core=%u port=%u len=%u eth_src=%s eth_dst=%s ether_type=0x%04x\n",
               lcore_id,
               port,
               rte_pktmbuf_pkt_len(mbuf),
               src_mac,
               dst_mac,
               rte_be_to_cpu_16(eth_hdr->ether_type));
    }
}

static int
lcore_main(void *mbuf_pool)
{
    uint16_t port;


    RTE_ETH_FOREACH_DEV(port)
    if (rte_eth_dev_socket_id(port) >= 0 &&
        rte_eth_dev_socket_id(port) !=
            (int)rte_socket_id())
        printf("WARNING, port %u is on remote NUMA node to "
               "polling thread.\n\tPerformance will "
               "not be optimal.\n",
               port);

    printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
           rte_lcore_id());


    while (!force_quit)
    {
        // port=0;
        RTE_ETH_FOREACH_DEV(port)
        {
            struct rte_mbuf *bufs[BURST_SIZE];
            uint16_t nb_rx = rte_eth_rx_burst(port, 0,
                                              bufs, BURST_SIZE);

            // const uint16_t nb_tx = rte_eth_tx_burst(port, 0,
            //                                             bufs, nb_rx);

            // break;

            uint16_t lcore_id = rte_lcore_id();

            stats[lcore_id][port].rx += nb_rx;

            if (nb_rx > 0)
            {
                // uint64_t timestamp = rte_get_tsc_cycles();
                // uint64_t tsc_hz = rte_get_tsc_hz();
                // double timestamp_us = (double)timestamp / tsc_hz * 1e6;
                // struct rte_ether_hdr *ethernet_header;
                // struct rte_ipv4_hdr *pIP4Hdr;
                // u_int16_t ethernet_type;

                for (int i = 0; i < nb_rx; i++) {
                    struct rte_ether_hdr *ethernet_header;
                    struct rte_ipv4_hdr *pIP4Hdr = NULL;
                    uint16_t ethernet_type;
                    bool is_ipv4 = false;

                    ethernet_header = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);

                    struct rte_ether_addr ethernet_source = ethernet_header->src_addr;
                    struct rte_ether_addr ethernet_dest = ethernet_header->dst_addr;

                    ethernet_header->src_addr = ethernet_dest;
                    ethernet_header->dst_addr = ethernet_source;

                    ethernet_type = rte_be_to_cpu_16(ethernet_header->ether_type);

                    if (ethernet_type == RTE_ETHER_TYPE_IPV4)
                    {
                        is_ipv4 = true;

                        pIP4Hdr = rte_pktmbuf_mtod_offset(
                            bufs[i],
                            struct rte_ipv4_hdr *,
                            sizeof(struct rte_ether_hdr)
                        );

                        uint32_t ip_source = pIP4Hdr->src_addr;
                        uint32_t ip_dest = pIP4Hdr->dst_addr;

                        pIP4Hdr->src_addr = ip_dest;
                        pIP4Hdr->dst_addr = ip_source;

                        pIP4Hdr->hdr_checksum = 0;
                        pIP4Hdr->hdr_checksum = rte_ipv4_cksum(pIP4Hdr);
                    }

                    if (enable_logging) {
                        log_packet(port, lcore_id, bufs[i], ethernet_header, pIP4Hdr, is_ipv4);
                    }
                }
                

                const uint16_t nb_tx = rte_eth_tx_burst(port, 0, bufs, nb_rx);
                // printf("%u packets are received and %u are transmitted \n",nb_rx, nb_tx);
                stats[lcore_id][port].tx += nb_tx;
                stats[lcore_id][port].dropped += nb_rx - nb_tx;

                if (unlikely(nb_tx < nb_rx))
                {
                    uint16_t buf;

                    for (buf = nb_tx; buf < nb_rx; buf++)
                        rte_pktmbuf_free(bufs[buf]);
                }

            }
        }
    }

    return 0;
}

static void close_ports(void);
static void close_ports(void)
{
    uint16_t portid;
    int ret;
    uint16_t nb_ports;
    nb_ports = rte_eth_dev_count_avail();
    for (portid = 0; portid < nb_ports; portid++)
    {
        printf("Closing port %d...", portid);
        ret = rte_eth_dev_stop(portid);
        if (ret != 0)
            rte_exit(EXIT_FAILURE, "rte_eth_dev_stop: err=%s, port=%u\n",
                     strerror(-ret), portid);
        rte_eth_dev_close(portid);
        printf(" Done\n");
    }
}

static void print_summary(void) {
    uint16_t port;
    unsigned int lcore_id;

    uint64_t total_rx = 0;
    uint64_t total_tx = 0;
    uint64_t total_dropped = 0;
    uint64_t total_ipv4 = 0;

    printf("\n========== Packet Processing Summary ==========\n");

    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        RTE_ETH_FOREACH_DEV(port)
        {
            uint64_t rx = stats[lcore_id][port].rx;
            uint64_t tx = stats[lcore_id][port].tx;
            uint64_t dropped = stats[lcore_id][port].dropped;
            uint64_t ipv4 = stats[lcore_id][port].ipv4;

            if (rx == 0 && tx == 0 && dropped == 0 && ipv4 == 0)
                continue;

            printf("Core %u, Port %u:\n", lcore_id, port);
            printf("  RX packets      : %" PRIu64 "\n", rx);
            printf("  TX packets      : %" PRIu64 "\n", tx);
            printf("  Dropped packets : %" PRIu64 "\n", dropped);
            printf("  IPv4 packets    : %" PRIu64 "\n", ipv4);
        }
    }

    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        RTE_ETH_FOREACH_DEV(port)
        {
            total_rx += stats[lcore_id][port].rx;
            total_tx += stats[lcore_id][port].tx;
            total_dropped += stats[lcore_id][port].dropped;
            total_ipv4 += stats[lcore_id][port].ipv4;
        }
    }

    printf("-----------------------------------------------\n");
    printf("Total RX packets      : %" PRIu64 "\n", total_rx);
    printf("Total TX packets      : %" PRIu64 "\n", total_tx);
    printf("Total dropped packets : %" PRIu64 "\n", total_dropped);
    printf("Total IPv4 packets    : %" PRIu64 "\n", total_ipv4);
    printf("===============================================\n");
}


/* Initialization of Environment Abstraction Layer (EAL). 8< */
int main(int argc, char **argv)
{
    struct rte_mempool *mbuf_pool;
    uint16_t nb_ports;
    uint16_t portid;
    unsigned lcore_id;
    int ret;

    // char rules_file[MAX_FILE_NAME] = "/home/ubuntu/rof/.rof2.binary";

    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_panic("Cannot init EAL\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    argc -= ret;
    argv += ret;

    nb_ports = rte_eth_dev_count_avail();

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
                                        NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    RTE_ETH_FOREACH_DEV(portid)
    if (port_init(portid, mbuf_pool) != 0)
    {
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
                 portid);
    }
    else{
        printf("port %u initialized\n",portid);
    }

    // struct rte_cryptodev_info dev_info;
    // rte_cryptodev_info_get(0, &dev_info);
    // uint8_t driver_id = dev_info.driver_id;
    // printf("The crypto driver name is %u\n",driver_id);

    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        rte_eal_remote_launch(lcore_main, mbuf_pool, lcore_id);
    }

    rte_eal_mp_wait_lcore();

    print_summary();

    close_ports();

    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}