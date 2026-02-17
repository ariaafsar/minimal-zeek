#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
apt update -y
apt install -y curl wget gnupg2

curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
    | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" \
    | tee /etc/apt/sources.list.d/security:zeek.list

apt update -y

apt install -y zeek

/opt/zeek/bin/zeek --version


