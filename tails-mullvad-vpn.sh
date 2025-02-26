#!/bin/bash

# Set your Mullvad account number here
MULLVAD_ACCOUNT="1234123412341234"

# Configurable features
DNS="10.64.0.1"
ROTATION_INTERVAL="72"
OBFUSCATION_MODE="shadowsocks"
QUANTUM_RESISTANT="on"
USE_MULTIHOP="on"
LOG_FILE="/home/amnesia/Persistent/vpn_launch.log"

mkdir -p /home/amnesia/Persistent/WireGuard
CONFIG_DIR="/home/amnesia/Persistent/WireGuard"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print an error message and exit
die() {
	echo "[-] Error: $1" >&2
	exit 1
}

# Function to clean up temporary files
cleanup() {
    rm -f /tmp/tov.ovpn
}

# Set up trap to clean up temporary files on exit
trap cleanup EXIT
set -e

# Redirect all output to the log file
exec > >(tee -a "$LOG_FILE") 2>&1

# Check if the script is run as root
PROGRAM="${0##*/}"
ARGS=( "$@" )
SELF="${BASH_SOURCE[0]}"
[[ $SELF == */* ]] || SELF="./$SELF"
SELF="$(cd "${SELF%/*}" && pwd -P)/${SELF##*/}"
[[ $UID == 0 ]] || exec sudo -p "[?] $PROGRAM must be run as root. Please enter the password for %u to continue: " -- "$BASH" -- "$SELF" "${ARGS[@]}"
echo "info: Running as root."

# Check Bash version
[[ ${BASH_VERSINFO[0]} -ge 4 ]] || die "bash ${BASH_VERSINFO[0]} detected, when bash 4+ required"

# Check for required commands
for cmd in grep awk tr stat chmod apt-get curl jq; do
    if ! command_exists "$cmd"; then
        echo "error: Required command '$cmd' not found. Please install it and try again." >&2
        apt-get update
        apt-get install -y "$cmd"
    fi
done

echo "info: Updating ferm configuration..."
# Update ferm configuration to allow reaching api.mullvad.net the internet
if ! grep -q "White-list access to api.mullvad.net for user root" /etc/ferm/ferm.conf; then
    awk '/Local resources/{print "            # White-list access to api.mullvad.net for user root" RS "            daddr 45.83.223.193 proto tcp dport 443 {" RS "                    mod owner uid-owner root ACCEPT;" RS "            }"  RS RS $0;next}1' /etc/ferm/ferm.conf >/tmp/ferm.conf && mv /tmp/ferm.conf /etc/ferm/ferm.conf
    echo "info: Ferm configuration updated for api.mullvad.net API server access."
else
    echo "info: Ferm configuration already contains api.mullvad.net API server access."
fi

echo "info: Reloading ferm configuration..."
# Reload ferm configuration
rm -f /var/cache/ferm/*
/etc/init.d/ferm reload
echo "info: Ferm configuration reloaded."

echo "[+] Contacting Mullvad API for server locations."
declare -A SERVER_ENDPOINTS
declare -A SERVER_PUBLIC_KEYS
declare -A SERVER_COUNTRY
declare -A SERVER_CITY
declare -a SERVER_CODES
declare -A MULTIHOP_PORTS

RESPONSE="$(curl -LsS https://api.mullvad.net/public/relays/wireguard/v1/)" || die "Unable to connect to Mullvad API."
FIELDS="$(jq -r 'foreach .countries[] as $country (.; .; foreach $country.cities[] as $city (.; .; foreach $city.relays[] as $relay (.; .; $country.name, $city.name, $relay.hostname, $relay.public_key, $relay.ipv4_addr_in, $relay.multihop_port)))' <<<"$RESPONSE")" || die "Unable to parse response."
while read -r COUNTRY && read -r CITY && read -r HOSTNAME && read -r PUBKEY && read -r IPADDR && read -r MULTIHOP_PORT; do
    CODE="$HOSTNAME"
    SERVER_CODES+=( "$CODE" )
    SERVER_COUNTRY["$CODE"]="$COUNTRY"
    SERVER_CITY["$CODE"]="$CITY"
    SERVER_PUBLIC_KEYS["$CODE"]="$PUBKEY"
    SERVER_ENDPOINTS["$CODE"]="$IPADDR"
    MULTIHOP_PORTS["$CODE"]="$MULTIHOP_PORT"
done <<<"$FIELDS"

echo "[+] Writing WriteGuard configuration files."
for CODE in "${SERVER_CODES[@]}"; do
    CONFIGURATION_FILE="$CONFIG_DIR/$CODE.conf"
	umask 077
	rm -f "$CONFIGURATION_FILE.tmp"
	cat > "$CONFIGURATION_FILE.tmp" <<-_EOF
        Hostname = $CODE
		PublicKey = ${SERVER_PUBLIC_KEYS["$CODE"]}
		Endpoint = ${SERVER_ENDPOINTS["$CODE"]}
        MultihopPort = ${MULTIHOP_PORTS["$CODE"]}
        ServerCountry = ${SERVER_COUNTRY["$CODE"]}
        ServerCity = ${SERVER_CITY["$CODE"]}
	_EOF
	mv "$CONFIGURATION_FILE.tmp" "$CONFIGURATION_FILE"
done

# Function to select two random configuration files and set entry/exit nodes
CONFIG_FILES=("$CONFIG_DIR"/*.conf)

if [ ${#CONFIG_FILES[@]} -lt 2 ]; then
    die "Not enough configuration files in $CONFIG_DIR"
fi

# Select two random configuration files
ENTRY_FILE="${CONFIG_FILES[RANDOM % ${#CONFIG_FILES[@]}]}"
EXIT_FILE="${CONFIG_FILES[RANDOM % ${#CONFIG_FILES[@]}]}"

# Ensure ENTRY_FILE and EXIT_FILE are different
while [ "$ENTRY_FILE" = "$EXIT_FILE" ]; do
    EXIT_FILE="${CONFIG_FILES[RANDOM % ${#CONFIG_FILES[@]}]}"
done

# Read entry node information
ENTRY_COUNTRY=$(grep -i "ServerCountry" "$ENTRY_FILE" | awk -F'=' '{print $2}' | xargs)
ENTRY_CITY=$(grep -i "ServerCity" "$ENTRY_FILE" | awk -F'=' '{print $2}' | xargs)
ENTRY_SERVER=$(grep -i "Hostname" "$ENTRY_FILE" | awk -F'=' '{print $2}' | xargs)
ENTRY_SERVER_IP=$(grep -i "Endpoint" "$ENTRY_FILE" | awk -F'=' '{print $2}' | xargs)
echo "info: Selected entry node: $ENTRY_COUNTRY, $ENTRY_CITY, $ENTRY_SERVER"

# Read exit node information
EXIT_COUNTRY=$(grep -i "ServerCountry" "$EXIT_FILE" | awk -F'=' '{print $2}' | xargs)
EXIT_CITY=$(grep -i "ServerCity" "$EXIT_FILE" | awk -F'=' '{print $2}' | xargs)
EXIT_SERVER=$(grep -i "Hostname" "$EXIT_FILE" | awk -F'=' '{print $2}' | xargs)
echo "info: Selected exit node: $EXIT_COUNTRY, $EXIT_CITY, $EXIT_SERVER"

echo "info: Disabling IPv6 if not already disabled..."
# Disable IPv6 if not already disabled
grep "net.ipv6.conf.all.disable_ipv6 = 1" /etc/sysctl.conf || echo net.ipv6.conf.all.disable_ipv6 = 1 >> /etc/sysctl.conf
grep "net.ipv6.conf.default.disable_ipv6 = 1" /etc/sysctl.conf || echo net.ipv6.conf.default.disable_ipv6 = 1 >> /etc/sysctl.conf
sysctl -p
echo "info: IPv6 disabled."

echo "info: Checking if Mullvad VPN is installed..."
# Install Mullvad VPN if not already installed
if [ ! -f /usr/bin/mullvad ]; then
    echo "info: Mullvad VPN not found. Installing Mullvad VPN..."
    curl -fsSLo /usr/share/keyrings/mullvad-keyring.asc https://repository.mullvad.net/deb/mullvad-keyring.asc
    echo "deb [signed-by=/usr/share/keyrings/mullvad-keyring.asc arch=$( dpkg --print-architecture )] https://repository.mullvad.net/deb/stable $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/mullvad.list
    apt-get update
    apt-get install -y mullvad-vpn
    echo "info: Mullvad VPN installed."
else
    echo "info: Mullvad VPN is already installed."
fi

echo "info: Updating ferm configuration..."
# Update ferm configuration to allow VPN to reach the internet
if ! grep -q "White-list access to Openvpnserver:port for user root" /etc/ferm/ferm.conf; then
    awk '/Local resources/{print "            # White-list access to Openvpnserver:port for user root" RS "            daddr '"$ENTRY_SERVER_IP"' proto udp dport 51820 {" RS "                    mod owner uid-owner root ACCEPT;" RS "            }"  RS RS $0;next}1' /etc/ferm/ferm.conf >/tmp/ferm.conf && mv /tmp/ferm.conf /etc/ferm/ferm.conf
    echo "info: Ferm configuration updated for OpenVPN server access."
else
    echo "info: Ferm configuration already contains OpenVPN server access."
fi

# Update ferm configuration to allow TOR to connect only via VPN interface
if ! grep -q "# But only when using tun0." /etc/ferm/ferm.conf; then
    awk '/mod owner uid-owner debian-tor {/{print "            # But only when using tun0." RS "            outerface wg0 mod owner uid-owner debian-tor {";next}1' /etc/ferm/ferm.conf >/tmp/ferm.conf && mv /tmp/ferm.conf /etc/ferm/ferm.conf
    echo "info: Ferm configuration updated for wg0 interface."
else
    echo "info: Ferm configuration already contains wg0 interface."
fi

echo "info: Reloading ferm configuration..."
# Reload ferm configuration
rm -f /var/cache/ferm/*
/etc/init.d/ferm reload
echo "info: Ferm configuration reloaded."

echo "info: Logging into Mullvad account..."
# Log into Mullvad account
mullvad account login "$MULLVAD_ACCOUNT"

echo "info: Generating new WireGuard key..."
# Generate a new WireGuard key
mullvad tunnel set wireguard rotate-key

echo "info: Changing key rotation interval to $ROTATION_INTERVAL ..."
# Change the key rotation interval
mullvad tunnel set wireguard --rotation-interval "$ROTATION_INTERVAL"

echo "info: Verifying WireGuard key..."
# Verify WireGuard key
mullvad tunnel get

echo "info: Setting protocol to WireGuard..."
# Set the protocol to WireGuard
mullvad relay set tunnel-protocol wireguard

echo "info: Setting WireGuard server port..."
# Use a 51820 WireGuard server port
mullvad relay set tunnel wireguard --port 51820

echo "info: Enabling Multihop..."
# Enable Multihop
mullvad relay set tunnel wireguard --use-multihop "$USE_MULTIHOP"

echo "info: Setting WireGuard enty node..."
# Set entry node
mullvad relay set tunnel wireguard entry location "$ENTRY_COUNTRY" "$ENTRY_CITY" "$ENTRY_SERVER"

echo "info: Setting exit node..."
# Set exit node
mullvad relay set location "$EXIT_COUNTRY" "$EXIT_CITY" "$EXIT_SERVER"

echo "info: Enabling WireGuard TCP obfuscation..."
# Use WireGuard TCP obfuscation
mullvad obfuscation set mode "$OBFUSCATION_MODE"

echo "info: Enabling quantum-resistant WireGuard tunnel..."
# Use a quantum-resistant WireGuard tunnel
mullvad tunnel set wireguard --quantum-resistant "$QUANTUM_RESISTANT"

echo "info: Setting DNS content blockers..."
# DNS content blockers
mullvad dns set default --block-ads --block-trackers --block-malware --block-gambling

#echo "info: Setting custom DNS server..."
# Use custom DNS server
#mullvad dns set custom "$DNS_SERVER"

#echo "info: Allowing LAN access..."
# Enable LAN access
#mullvad lan set allow

echo "info: Updating DNS resolver..."
# Update DNS resolver
echo nameserver "$DNS" > /etc/resolv-over-clearnet.conf
#echo nameserver "$DNS_SERVER" > /etc/resolv-over-clearnet.conf
echo "info: DNS resolver updated."

echo "info: Connecting to Mullvad VPN..."
# Connect to Mullvad VPN
mullvad connect
mullvad status
