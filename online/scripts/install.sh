chmod +x nat64.sh && ./nat64.sh
echo "Run nat64.sh"
chmod +x host_tune.sh && sudo ./host_tune.sh
echo "Run hosdt_tune.sh"

sudo apt-get update > /dev/null 2>&1
sudo apt-get install -y build-essential > /dev/null 2>&1
sudo apt-get install -y python3-pip > /dev/null 2>&1
sudo pip3 install meson ninja > /dev/null 2>&1
sudo apt install -y python3-pyelftools > /dev/null 2>&1
sudo apt install -y libnuma-dev > /dev/null 2>&1
sudo apt install -y pkg-config > /dev/null 2>&1
sudo apt install net-tools > /dev/null 2>&1
sudo apt install iperf3 > /dev/null 2>&1
sudo apt install hping3 > /dev/null 2>&1
sudo apt install tcpdump > /dev/null 2>&1
echo "Dependencies installed"

echo "Downloading mellanox SDK"
wget https://content.mellanox.com/ofed/MLNX_OFED-23.07-0.5.0.0/MLNX_OFED_LINUX-23.07-0.5.0.0-ubuntu20.04-x86_64.tgz > /dev/null 2>&1
echo "Unzip and install mellanox SDK"
tar xvfz MLNX_OFED_LINUX-23.07-0.5.0.0-ubuntu20.04-x86_64.tgz > /dev/null 2>&1
cd MLNX_OFED_LINUX-23.07-0.5.0.0-ubuntu20.04-x86_64 && echo "y" | sudo ./mlnxofedinstall --upstream-libs --dpdk --basic --without-fw-update > /dev/null 2>&1
echo "Mellanox SDK Ready"

echo "Downloading DPDK"
git clone http://dpdk.org/git/dpdk > /dev/null 2>&1
cd dpdk &&  sudo meson build && cd build && sudo ninja && sudo ninja install && sudo ldconfig  > /dev/null 2>&1
echo "DPDK Ready"

sudo /etc/init.d/openibd restart  > /dev/null 2>&1
