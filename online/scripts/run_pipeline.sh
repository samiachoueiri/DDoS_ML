# /home/admin/p4c/build/p4c-dpdk --arch pna main.p4 -o lab7.spec

export RTE_INSTALL_DIR=/home/ubuntu/dpdk
export LAB_DIR=/home/ubuntu

echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# $RTE_INSTALL_DIR/examples/pipeline/build/pipeline -c 0x3 --vdev=net_tap0,mac="00:00:00:00:00:01" --vdev=net_tap1,mac="00:00:00:00:00:02" --vdev=net_tap2,mac="00:00:00:00:00:03" --  -s $LAB_DIR/lab7.cli

# echo "disable ipv6 ------------------"
ip netns del h1 > /dev/null 2>&1
ip netns del h2 > /dev/null 2>&1
ip netns del h3 > /dev/null 2>&1

tmp_file=$(mktemp)

stdbuf -oL $RTE_INSTALL_DIR/examples/pipeline/build/pipeline -c 0x3 --vdev=net_tap0,mac="00:00:00:00:00:01" --vdev=net_tap1,mac="00:00:00:00:00:02" --vdev=net_tap2,mac="00:00:00:00:00:03" --  -s $LAB_DIR/lab7.cli > $tmp_file & 

sleep 3

ip netns add h1
ip netns add h2
ip netns add h3

ip link set dtap0 netns h1
ip link set dtap1 netns h2
ip link set dtap2 netns h3

# sysctl -w net.ipv6.conf.all.disable_ipv6=1 --quiet
ip netns exec h1 sysctl -w net.ipv6.conf.all.disable_ipv6=1 --quiet
ip netns exec h2 sysctl -w net.ipv6.conf.all.disable_ipv6=1 --quiet
ip netns exec h3 sysctl -w net.ipv6.conf.all.disable_ipv6=1 --quiet

tail -f -n -0  $tmp_file
