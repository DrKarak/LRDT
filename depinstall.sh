#!/bin/sh

[ $(id -u) != 0 ] && { echo "You must be root to install dependencies"; exit; }

if [ -f /usr/bin/yum ]; then
    yum -y install gcc make kernel-devel net-tools
    exit
fi

if [ -f /usr/bin/pacman ]; then
    pacman -Syy
    pacman -S gcc make linux-headers net-tools
    exit
fi

if [ -f /usr/bin/apt-get ]; then
    apt-get install --yes gcc make linux-headers-$(uname -r) net-tools
    exit
fi

echo "\033[0;31mUnable to determine package manager. Please install dependencies manually:\033[0m"
echo "gcc make net-tools linux-headers-$(uname -r)"