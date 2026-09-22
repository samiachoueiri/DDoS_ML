/*
 * Simple DPDK packet reflector
 *
 * What this application does:
 *   1. Initializes DPDK EAL.
 *   2. Creates an mbuf pool for packet buffers.
 *   3. Initializes every DPDK-enabled Ethernet port.
 *   4. Starts one worker core.
 *   5. The worker polls all ports, reflects packets, and sends them back out.
 *   6. On Ctrl+C, it prints a packet-processing summary and exits cleanly.
 *
 * Current core/queue model:
 *   - One worker core handles all enabled ports.
 *   - Each port uses RX queue 0 and TX queue 0.
 *
 * This is intentional. If multiple worker cores poll the same RX/TX queue,
 * packet handling can become unsafe. To use multiple workers correctly, create
 * multiple RX/TX queues and assign each queue to exactly one worker core.
 */

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

/* -------------------------------------------------------------------------
 * 1. Application configuration
 * ------------------------------------------------------------------------- */

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8192
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE 1000

/* Set to true for debugging. Per-packet printf is very slow. */
static bool enable_logging = false;

/* Set by Ctrl+C / SIGTERM so worker loops can exit cleanly. */
static volatile sig_atomic_t force_quit = 0;

/* -------------------------------------------------------------------------
 * 2. Packet statistics
 * ------------------------------------------------------------------------- */

struct port_stats {
    uint64_t rx;
    uint64_t tx;
    uint64_t dropped;
    uint64_t ipv4;
};

static struct port_stats stats[RTE_MAX_ETHPORTS];

/* -------------------------------------------------------------------------
 * 3. Signal handling
 * ------------------------------------------------------------------------- */

static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal %d received, stopping...\n", signum);
        force_quit = 1;
    }
}

/* -------------------------------------------------------------------------
 * 4. Port setup
 * -------------------------------------------------------------------------
 * Each DPDK port needs:
 *   - rte_eth_dev_configure(): configure number of RX/TX queues.
 *   - rte_eth_rx_queue_setup(): allocate/configure RX queue descriptors.
 *   - rte_eth_tx_queue_setup(): allocate/configure TX queue descriptors.
 *   - rte_eth_dev_start(): start the device.
 *
 * This example uses one RX queue and one TX queue per port.
 */

static int
port_init(uint16_t port_id, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rx_conf;
    struct rte_eth_txconf tx_conf;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    const uint16_t rx_queues = 1;
    const uint16_t tx_queues = 1;
    int ret;

    if (!rte_eth_dev_is_valid_port(port_id))
        return -1;

    memset(&port_conf, 0, sizeof(port_conf));

    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0) {
        printf("Failed to get port %u info: %s\n", port_id, strerror(-ret));
        return ret;
    }

    ret = rte_eth_dev_configure(port_id, rx_queues, tx_queues, &port_conf);
    if (ret != 0)
        return ret;

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
    if (ret != 0)
        return ret;

    rx_conf = dev_info.default_rxconf;
    ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd,
                                 rte_eth_dev_socket_id(port_id),
                                 &rx_conf, mbuf_pool);
    if (ret < 0)
        return ret;

    tx_conf = dev_info.default_txconf;
    tx_conf.offloads = port_conf.txmode.offloads;
    ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd,
                                 rte_eth_dev_socket_id(port_id),
                                 &tx_conf);
    if (ret < 0)
        return ret;

    ret = rte_eth_dev_start(port_id);
    if (ret < 0)
        return ret;

    ret = rte_eth_promiscuous_enable(port_id);
    if (ret != 0)
        printf("Warning: could not enable promiscuous mode on port %u: %s\n",
               port_id, strerror(-ret));

    printf("Port %u initialized with 1 RX queue and 1 TX queue\n", port_id);
    return 0;
}

/* -------------------------------------------------------------------------
 * 5. Packet logging
 * -------------------------------------------------------------------------
 * This function prints one line per packet. It is useful for debugging only.
 * It prints the packet after reflection, so MAC/IP addresses are already
 * swapped when they appear in the log.
 */

static void
log_packet(uint16_t port_id,
           unsigned int lcore_id,
           struct rte_mbuf *mbuf,
           struct rte_ether_hdr *eth_hdr,
           struct rte_ipv4_hdr *ipv4_hdr,
           bool is_ipv4)
{
    char src_mac[RTE_ETHER_ADDR_FMT_SIZE];
    char dst_mac[RTE_ETHER_ADDR_FMT_SIZE];

    rte_ether_format_addr(src_mac, sizeof(src_mac), &eth_hdr->src_addr);
    rte_ether_format_addr(dst_mac, sizeof(dst_mac), &eth_hdr->dst_addr);

    if (is_ipv4 && ipv4_hdr != NULL) {
        uint32_t src_ip = rte_be_to_cpu_32(ipv4_hdr->src_addr);
        uint32_t dst_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);

        printf("core=%u port=%u len=%u eth_src=%s eth_dst=%s "
               "ipv4_src=%u.%u.%u.%u ipv4_dst=%u.%u.%u.%u\n",
               lcore_id,
               port_id,
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
               port_id,
               rte_pktmbuf_pkt_len(mbuf),
               src_mac,
               dst_mac,
               rte_be_to_cpu_16(eth_hdr->ether_type));
    }
}

/* -------------------------------------------------------------------------
 * 6. Packet parsing, processing, and deparsing
 * -------------------------------------------------------------------------
 * In DPDK, packet data lives inside an rte_mbuf.
 *
 * Parsing:
 *   - Get a pointer to the Ethernet header.
 *   - Check the Ethernet type.
 *   - If it is IPv4, get a pointer to the IPv4 header.
 *
 * Processing:
 *   - Swap Ethernet source/destination addresses.
 *   - If IPv4, swap IPv4 source/destination addresses.
 *
 * Deparsing:
 *   - There is no separate serialization step here.
 *   - We modify the headers directly inside the mbuf.
 *   - When rte_eth_tx_burst() transmits the mbuf, it sends the modified packet.
 */

static void
reflect_packet(uint16_t port_id, unsigned int lcore_id, struct rte_mbuf *mbuf)
{
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr = NULL;
    struct rte_ether_addr tmp_mac;
    uint16_t ether_type;
    bool is_ipv4 = false;

    if (rte_pktmbuf_pkt_len(mbuf) < sizeof(struct rte_ether_hdr))
        return;

    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

    /* Processing step 1: reflect at Ethernet level. */
    tmp_mac = eth_hdr->src_addr;
    eth_hdr->src_addr = eth_hdr->dst_addr;
    eth_hdr->dst_addr = tmp_mac;

    ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

    if (ether_type == RTE_ETHER_TYPE_IPV4) {
        if (rte_pktmbuf_pkt_len(mbuf) <
            sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr))
            goto log_and_return;

        is_ipv4 = true;
        stats[port_id].ipv4++;

        ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf,
                                           struct rte_ipv4_hdr *,
                                           sizeof(struct rte_ether_hdr));

        /* Processing step 2: reflect at IPv4 level. */
        uint32_t tmp_ip = ipv4_hdr->src_addr;
        ipv4_hdr->src_addr = ipv4_hdr->dst_addr;
        ipv4_hdr->dst_addr = tmp_ip;

        /* Recompute the IPv4 header checksum after changing addresses. */
        ipv4_hdr->hdr_checksum = 0;
        ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
    }

log_and_return:
    if (enable_logging)
        log_packet(port_id, lcore_id, mbuf, eth_hdr, ipv4_hdr, is_ipv4);
}

/* -------------------------------------------------------------------------
 * 7. Core setup and forwarding loop
 * -------------------------------------------------------------------------
 * This worker core does the hot path:
 *   RX burst -> parse/process/deparse each packet -> TX burst
 *
 * It polls every available DPDK port, but only queue 0 on each port.
 */

static int
forwarding_loop(void *arg)
{
    unsigned int lcore_id = rte_lcore_id();
    uint16_t port_id;

    (void)arg;

    RTE_ETH_FOREACH_DEV(port_id) {
        if (rte_eth_dev_socket_id(port_id) >= 0 &&
            rte_eth_dev_socket_id(port_id) != (int)rte_socket_id()) {
            printf("Warning: port %u is on a remote NUMA node from core %u. "
                   "Performance may not be optimal.\n",
                   port_id, lcore_id);
        }
    }

    printf("\nCore %u started forwarding. Press Ctrl+C to stop.\n", lcore_id);

    while (!force_quit) {
        RTE_ETH_FOREACH_DEV(port_id) {
            struct rte_mbuf *bufs[BURST_SIZE];
            uint16_t nb_rx;
            uint16_t nb_tx;

            nb_rx = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);
            if (nb_rx == 0)
                continue;

            stats[port_id].rx += nb_rx;

            for (uint16_t i = 0; i < nb_rx; i++)
                reflect_packet(port_id, lcore_id, bufs[i]);

            nb_tx = rte_eth_tx_burst(port_id, 0, bufs, nb_rx);
            stats[port_id].tx += nb_tx;
            stats[port_id].dropped += nb_rx - nb_tx;

            if (unlikely(nb_tx < nb_rx)) {
                for (uint16_t i = nb_tx; i < nb_rx; i++)
                    rte_pktmbuf_free(bufs[i]);
            }
        }
    }

    printf("Core %u stopped forwarding.\n", lcore_id);
    return 0;
}

/* -------------------------------------------------------------------------
 * 8. Cleanup and summary
 * ------------------------------------------------------------------------- */

static void
print_summary(void)
{
    uint16_t port_id;
    uint64_t total_rx = 0;
    uint64_t total_tx = 0;
    uint64_t total_dropped = 0;
    uint64_t total_ipv4 = 0;

    printf("\n========== Packet Processing Summary ==========\n");

    RTE_ETH_FOREACH_DEV(port_id) {
        printf("Port %u:\n", port_id);
        printf("  RX packets      : %" PRIu64 "\n", stats[port_id].rx);
        printf("  TX packets      : %" PRIu64 "\n", stats[port_id].tx);
        printf("  Dropped packets : %" PRIu64 "\n", stats[port_id].dropped);
        printf("  IPv4 packets    : %" PRIu64 "\n", stats[port_id].ipv4);

        total_rx += stats[port_id].rx;
        total_tx += stats[port_id].tx;
        total_dropped += stats[port_id].dropped;
        total_ipv4 += stats[port_id].ipv4;
    }

    printf("-----------------------------------------------\n");
    printf("Total RX packets      : %" PRIu64 "\n", total_rx);
    printf("Total TX packets      : %" PRIu64 "\n", total_tx);
    printf("Total dropped packets : %" PRIu64 "\n", total_dropped);
    printf("Total IPv4 packets    : %" PRIu64 "\n", total_ipv4);
    printf("===============================================\n");
}

static void
close_ports(void)
{
    uint16_t port_id;

    RTE_ETH_FOREACH_DEV(port_id) {
        int ret;

        printf("Closing port %u...", port_id);
        ret = rte_eth_dev_stop(port_id);
        if (ret != 0) {
            printf(" failed to stop: %s\n", strerror(-ret));
            continue;
        }

        rte_eth_dev_close(port_id);
        printf(" done\n");
    }
}

/* -------------------------------------------------------------------------
 * 9. Main: DPDK setup, port setup, core launch
 * ------------------------------------------------------------------------- */

int
main(int argc, char **argv)
{
    struct rte_mempool *mbuf_pool;
    uint16_t nb_ports;
    uint16_t port_id;
    unsigned int worker_lcore = RTE_MAX_LCORE;
    unsigned int lcore_id;
    int ret;

    /* Initialize DPDK EAL. This parses arguments like -l, -n, and -a. */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot initialize DPDK EAL\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No DPDK Ethernet ports found\n");

    printf("DPDK detected %u Ethernet port(s)\n", nb_ports);

    /* Create the packet-buffer pool used by all RX queues. */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
                                        NUM_MBUFS * nb_ports,
                                        MBUF_CACHE_SIZE,
                                        0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE,
                                        rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initialize every DPDK-enabled port. */
    RTE_ETH_FOREACH_DEV(port_id) {
        ret = port_init(port_id, mbuf_pool);
        if (ret != 0)
            rte_exit(EXIT_FAILURE, "Cannot initialize port %u: %s\n",
                     port_id, strerror(-ret));
    }

    /* Pick one worker core. The main core only does setup and cleanup. */
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        worker_lcore = lcore_id;
        break;
    }

    if (worker_lcore == RTE_MAX_LCORE)
        rte_exit(EXIT_FAILURE, "No worker core available. Use at least two cores, for example: -l 0-1\n");

    printf("Main core: %u\n", rte_get_main_lcore());
    printf("Worker core: %u\n", worker_lcore);

    rte_eal_remote_launch(forwarding_loop, NULL, worker_lcore);
    rte_eal_wait_lcore(worker_lcore);

    print_summary();
    close_ports();

    ret = rte_eal_cleanup();
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "EAL cleanup failed\n");

    return 0;
}
