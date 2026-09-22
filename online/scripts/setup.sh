#!/bin/bash

# Define the lines to be added
lines_to_add=(
    "net.ipv6.conf.all.disable_ipv6 = 1"
    "net.ipv6.conf.default.disable_ipv6 = 1"
    "net.ipv6.conf.lo.disable_ipv6 = 1"
)

# Backup the original sysctl.conf file
cp /etc/sysctl.conf /etc/sysctl.conf.bak

# Append each line to /etc/sysctl.conf
for line in "${lines_to_add[@]}"; do
    # Check if the line already exists
    if ! grep -Fxq "$line" /etc/sysctl.conf; then
        echo "$line" >> /etc/sysctl.conf
        echo "Added: $line"
    else
        echo "Skipped (already exists): $line"
    fi
done

# Reload sysctl settings
sysctl -p

echo "Completed updating /etc/sysctl.conf"
# sudo reboot
