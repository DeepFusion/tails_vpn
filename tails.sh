#!/bin/bash

LOG_FILE="/home/amnesia/Persistent/vpn_launch.log"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to clean up temporary files
cleanup() {
    rm -f /tmp/tov.ovpn
}

# Set up trap to clean up temporary files on exit
trap cleanup EXIT

# Redirect all output to the log file
exec > >(tee -a "$LOG_FILE") 2>&1

# Check if the script is run as root
if [ ! "$(id -u)" = 0 ] ; then
    echo "error: This script needs to be run using 'sudo SCRIPT' or in 'root terminal'" >&2
    echo "exiting now" >&2
    exit 1
fi

# Check if a file name is provided as a parameter
if [ -z "$1" ]; then
    echo "error: No file name provided. Usage: sudo $0 <file_name>" >&2
    exit 1
fi

# Assign the provided file name to a variable
OVPN_FILE="$1"

# Check if the provided file exists
if [ ! -f "$OVPN_FILE" ]; then
    echo "error: File '$OVPN_FILE' not found!" >&2
    exit 1
fi

# Check for required commands
for cmd in grep awk tr stat chmod apt-get; do
    if ! command_exists "$cmd"; then
        echo "error: Required command '$cmd' not found. Please install it and try again." >&2
        exit 1
    fi
done

echo "info: Checking for carriage return characters in '$OVPN_FILE'..."
# Remove carriage return characters if present
if grep -r $'\r' "$OVPN_FILE" >/dev/null; then
    echo "info: Carriage return characters found. Removing them..."
    unset tovcfgperm
    tovcfgperm=$(stat -c%a "$OVPN_FILE")
    tr -d $'\r' < "$OVPN_FILE" >/tmp/tov.ovpn && mv /tmp/tov.ovpn "$OVPN_FILE"
    chmod "$tovcfgperm" "$OVPN_FILE"
    unset tovcfgperm
    echo "info: Carriage return characters removed."
else
    echo "info: No carriage return characters found."
fi

echo "info: Disabling IPv6 if not already disabled..."
# Disable IPv6 if not already disabled
grep "net.ipv6.conf.all.disable_ipv6 = 1" /etc/sysctl.conf || echo net.ipv6.conf.all.disable_ipv6 = 1 >> /etc/sysctl.conf
grep "net.ipv6.conf.default.disable_ipv6 = 1" /etc/sysctl.conf || echo net.ipv6.conf.default.disable_ipv6 = 1 >> /etc/sysctl.conf
sysctl -p
echo "info: IPv6 disabled."

echo "info: Extracting VPN server details from '$OVPN_FILE'..."
# Extract VPN server details from the provided file
unset vpnserver_ip
unset vpnserver_port
unset vpnserver_proto
vpnserver_ip=$(grep "^remote " "$OVPN_FILE" | awk '{print $2}')
if [[ -z "$vpnserver_ip" ]] ; then echo 'error: VPN server IP not found in the provided file!' >&2; exit 1; fi
if ! [[ "$vpnserver_ip" =~ ^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$ ]] ; then echo "error: 'remote' appears not to be an IP address in the provided file" >&2; exit 1; fi
vpnserver_port=$(grep "^remote " "$OVPN_FILE" | awk '{print $3}')
if [[ -z "$vpnserver_port" ]] 
then
    vpnserver_port=$(grep "^port " "$OVPN_FILE" | awk '{print $2}')
fi
if [[ -z "$vpnserver_port" ]] ; then echo 'error: VPN server port not found in the provided file!' >&2; exit 1; fi
if ! [[ "$vpnserver_port" =~ ^[0-9]+$ ]] ; then echo "error: 'port' appears not to be an integer (number) in the provided file" >&2; exit 1; fi
vpnserver_proto=$(grep "^remote " "$OVPN_FILE" | awk '{print $4}')
if [[ -z "$vpnserver_proto" ]] 
then
    vpnserver_proto=$(grep "^proto " "$OVPN_FILE" | awk '{print $2}')
fi
if [[ -z "$vpnserver_proto" ]] ; then echo 'info: VPN server protocol not found in the provided file, using UDP' >&2; vpnserver_proto=udp; fi
echo "info: VPN server details extracted: IP=$vpnserver_ip, Port=$vpnserver_port, Protocol=$vpnserver_proto."

echo "info: Checking if OpenVPN is installed..."
# Install OpenVPN if not already installed
if [ ! -f /usr/sbin/openvpn ]; then
    echo "info: OpenVPN not found. Installing OpenVPN..."
    apt-cache search openvpn 2>/dev/null | grep "openvpn - virtual private network daemon" || apt-get update
    apt-get install -y openvpn
    echo "info: OpenVPN installed."
else
    echo "info: OpenVPN is already installed."
fi

echo "info: Updating ferm configuration..."
# Update ferm configuration
if ! grep -q "White-list access to Openvpnserver:port for user root" /etc/ferm/ferm.conf; then
    awk '/Local resources/{print "            # White-list access to Openvpnserver:port for user root" RS "            daddr '"$vpnserver_ip"' proto '"$vpnserver_proto"' dport '"$vpnserver_port"' {" RS "                    mod owner uid-owner root ACCEPT;" RS "            }"  RS RS $0;next}1' /etc/ferm/ferm.conf >/tmp/ferm.conf && mv /tmp/ferm.conf /etc/ferm/ferm.conf
    echo "info: Ferm configuration updated for OpenVPN server access."
else
    echo "info: Ferm configuration already contains OpenVPN server access."
fi
if ! grep -q "# But only when using tun0." /etc/ferm/ferm.conf; then
    awk '/mod owner uid-owner debian-tor {;/{print "            # But only when using tun0." RS "            outerface tun0 mod owner uid-owner debian-tor {;";next}1' /etc/ferm/ferm.conf >/tmp/ferm.conf && mv /tmp/ferm.conf /etc/ferm/ferm.conf
    echo "info: Ferm configuration updated for tun0 interface."
else
    echo "info: Ferm configuration already contains tun0 interface."
fi

echo "info: Reloading ferm configuration..."
# Reload ferm configuration
rm -f /var/cache/ferm/*
/etc/init.d/ferm reload
echo "info: Ferm configuration reloaded."

echo "info: Updating DNS resolver..."
# Update DNS resolver
echo nameserver 10.8.0.1 > /etc/resolv-over-clearnet.conf
echo "info: DNS resolver updated."

echo "info: Starting OpenVPN with the provided configuration file..."
# Start OpenVPN with the provided configuration file
openvpn --config "$OVPN_FILE"
echo "info: OpenVPN started."
