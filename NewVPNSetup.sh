#!/bin/bash

# Check if script is run with sudo
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root (sudo)."
    exit 1
fi

# Check if dialog is installed
if ! command -v dialog &>/dev/null; then
    apt update && apt install -y dialog
fi

# Function to display error and exit
error_exit() {
    dialog --msgbox "Error: $1" 10 40
    exit 1
}

# Install dependencies
dialog --msgbox "Installing dependencies: OpenVPN, Nginx, UFW, and others..." 10 40
apt update && apt install -y openvpn nginx ufw qrencode curl wget || error_exit "Failed to install dependencies."

# Prompt for server type
server_type=$(dialog --menu "Select server type:" 15 40 3 \
    1 "Home Server" \
    2 "Home Computer as Server" \
    3 "VPS" 2>&1 >/dev/tty) || exit 1

# Get network interface
interface=$(ip addr | grep -E '^[0-9]+: (eth|ens|enp|wlan)[0-9]+' | awk '{print $2}' | cut -d: -f1 | head -n 1)
[ -z "$interface" ] && error_exit "No network interface found."

# Get server IP (first non-loopback IPv4 address)
server_ip=$(ip addr show $interface | grep -E 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' | cut -d/ -f1 | head -n 1)
[ -z "$server_ip" ] && error_exit "No IPv4 address found on interface $interface."

# Prompt for OpenVPN DNS configuration
dns_choice=$(dialog --title "OpenVPN DNS Configuration" --menu \
    "DNS (Domain Name System) converts website names (like google.com) to IP addresses your device can connect to.\nChoose a DNS provider for your VPN to ensure fast and secure browsing:" 20 60 6 \
    1 "Google DNS (fast, reliable)" \
    2 "Cloudflare DNS (privacy-focused)" \
    3 "OpenDNS (Cisco, with filtering options)" \
    4 "Quad9 DNS (security-focused)" \
    5 "AdGuard DNS (ad-blocking)" \
    6 "Custom DNS (enter your own)" 2>&1 >/dev/tty) || exit 1

# Map DNS choice to openvpn-install values
case $dns_choice in
    1) export DNS=3 ;;  # Google
    2) export DNS=5 ;;  # Cloudflare
    3) export DNS=4 ;;  # OpenDNS
    4) export DNS=11 ;; # Quad9
    5) export DNS=12 ;; # AdGuard
    6)
        custom_dns=$(dialog --inputbox "Enter two custom DNS servers (space-separated, e.g., 8.8.8.8 8.8.4.4):" 10 50 2>&1 >/dev/tty) || exit 1
        [ -z "$custom_dns" ] && error_exit "Custom DNS cannot be empty."
        export DNS=10
        export CUSTOM_DNS="$custom_dns"
        ;;
esac

# Configure OpenVPN
dialog --msgbox "Configuring OpenVPN with selected DNS..." 10 40
wget -O /tmp/openvpn-install.sh https://raw.githubusercontent.com/angristan/openvpn-install/master/openvpn-install.sh || error_exit "Failed to download OpenVPN installer."
chmod +x /tmp/openvpn-install.sh

# Set environment variables for non-interactive install
export AUTO_INSTALL=y
export APPROVE_INSTALL=y
export APPROVE_IP=y
export IPV6_SUPPORT=n
export PORT_CHOICE=1  # Default port 1194
export PROTOCOL_CHOICE=1  # UDP
export COMPRESSION_ENABLED=n
export CUSTOMIZE_ENC=n
export CLIENT=client
export PASS=1  # Passwordless

# Run in /root to save client.ovpn there
cd /root
/tmp/openvpn-install.sh || error_exit "OpenVPN installation failed."

# Store OpenVPN config for dialog display
client_config="/root/client.ovpn"
[ ! -f "$client_config" ] && error_exit "OpenVPN client config not found."
openvpn_config=$(cat "$client_config")

# Configure UFW (base rules)
ufw allow 1194/udp
ufw allow OpenSSH
ufw --force enable
ufw status | dialog --programbox "UFW Status" 20 60

# Prompt for OpenVPN website deployment
deploy_openvpn_web=0
dialog --yesno "Deploy a website with OpenVPN settings and QR code?" 10 40
if [ $? -eq 0 ]; then
    deploy_openvpn_web=1
fi

# Prompt for WireGuard deployment
deploy_wireguard=0
wireguard_config=""
dialog --yesno "Deploy WireGuard alongside OpenVPN?" 10 40
if [ $? -eq 0 ]; then
    deploy_wireguard=1
    # Install and configure WireGuard
    apt install -y wireguard || error_exit "Failed to install WireGuard."
    mkdir -p /etc/wireguard
    wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
    client_key=$(wg genkey)
    client_pub=$(echo "$client_key" | wg pubkey)
    
    # Server config
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $(cat /etc/wireguard/server.key)
Address = 10.0.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $interface -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $interface -j MASQUERADE

[Peer]
PublicKey = $client_pub
AllowedIPs = 10.0.0.2/32
EOF

    # Client config
    cat > /root/wg-client.conf << EOF
[Interface]
PrivateKey = $client_key
Address = 10.0.0.2/24
DNS = 8.8.8.8

[Peer]
PublicKey = $(cat /etc/wireguard/server.pub)
Endpoint = $server_ip:51820
AllowedIPs = 0.0.0.0/0, ::/0
EOF

    # Store WireGuard config for dialog display
    wireguard_config=$(cat /root/wg-client.conf)

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

    # Start WireGuard
    wg-quick up wg0
    systemctl enable wg-quick@wg0
    ufw allow 51820/udp
fi

# Configure Nginx if either website is deployed
deployed_web=0
if [ $deploy_openvpn_web -eq 1 ] || [ $deploy_wireguard -eq 1 ]; then
    deployed_web=1
    # Allow HTTP and HTTPS in UFW
    ufw allow 80/tcp
    ufw allow 443/tcp

    # Disable default site
    rm -f /etc/nginx/sites-enabled/default

    # Create web directory
    mkdir -p /var/www/vpn

    # Create single site config
    cat > /etc/nginx/sites-available/vpn-site << EOF
server {
    listen 80;
    server_name _;
    root /var/www/vpn;
    index openvpn.html wireguard.html;

    location /openvpn.html {
        try_files \$uri \$uri/ /openvpn.html;
    }

    location /wireguard.html {
        try_files \$uri \$uri/ /wireguard.html;
    }
}
EOF

    # Enable the site
    ln -sf /etc/nginx/sites-available/vpn-site /etc/nginx/sites-enabled/vpn-site
    systemctl restart nginx

    # Deploy OpenVPN webpage
    if [ $deploy_openvpn_web -eq 1 ]; then
        cp "$client_config" /var/www/vpn/client.ovpn
        qrencode -o /var/www/vpn/qr-openvpn.png < "$client_config" || error_exit "Failed to generate OpenVPN QR code."
        cat > /var/www/vpn/openvpn.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenVPN Configuration</title>
    <style>
        body {
            background-color: #2d2d2d;
            color: #e0e0e0;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            background-color: #3c3c3c;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.5);
            max-width: 600px;
            width: 100%;
        }
        h1 {
            color: #00ccff;
            text-align: center;
        }
        p {
            line-height: 1.6;
            margin: 10px 0;
        }
        a {
            color: #00ff88;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        img {
            display: block;
            margin: 20px auto;
            max-width: 100%;
        }
        .instructions {
            background-color: #4a4a4a;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
        }
        .highlight {
            color: #ffcc00;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>OpenVPN Configuration</h1>
        <p>Welcome to your OpenVPN setup. Follow these steps to connect:</p>
        <div class="instructions">
            <p><span class="highlight">Step 1:</span> Download the VPN client configuration file: <a href="client.ovpn">Download client.ovpn</a></p>
            <p><span class="highlight">Step 2:</span> Install an OpenVPN client on your device (e.g., OpenVPN Connect for mobile or desktop).</p>
            <p><span class="highlight">Step 3:</span> Import the <a href="client.ovpn">client.ovpn</a> file into your VPN client.</p>
            <p><span class="highlight">Step 4:</span> Alternatively, scan this QR code with your mobile VPN app:</p>
            <img src="qr-openvpn.png" alt="OpenVPN QR Code">
            <p><span class="highlight">Step 5:</span> Connect to the VPN and enjoy secure browsing!</p>
        </div>
    </div>
</body>
</html>
EOF
    fi

    # Deploy WireGuard webpage
    if [ $deploy_wireguard -eq 1 ]; then
        cp /root/wg-client.conf /var/www/vpn/wg-client.conf
        qrencode -o /var/www/vpn/wg-qr.png < /root/wg-client.conf || error_exit "Failed to generate WireGuard QR code."
        cat > /var/www/vpn/wireguard.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WireGuard Configuration</title>
    <style>
        body {
            background-color: #2d2d2d;
            color: #e0e0e0;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            background-color: #3c3c3c;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.5);
            max-width: 600px;
            width: 100%;
        }
        h1 {
            color: #00ccff;
            text-align: center;
        }
        p {
            line-height: 1.6;
            margin: 10px 0;
        }
        a {
            color: #00ff88;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        img {
            display: block;
            margin: 20px auto;
            max-width: 100%;
        }
        .instructions {
            background-color: #4a4a4a;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
        }
        .highlight {
            color: #ffcc00;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>WireGuard Configuration</h1>
        <p>Welcome to your WireGuard VPN setup. Follow these steps to connect:</p>
        <div class="instructions">
            <p><span class="highlight">Step 1:</span> Download the WireGuard client configuration file: <a href="wg-client.conf">Download wg-client.conf</a></p>
            <p><span class="highlight">Step 2:</span> Install the WireGuard client on your device (e.g., WireGuard app for mobile or desktop).</p>
            <p><span class="highlight">Step 3:</span> Import the <a href="wg-client.conf">wg-client.conf</a> file into your WireGuard client.</p>
            <p><span class="highlight">Step 4:</span> Alternatively, scan this QR code with your mobile WireGuard app:</p>
            <img src="wg-qr.png" alt="WireGuard QR Code">
            <p><span class="highlight">Step 5:</span> Connect to the VPN and enjoy secure browsing!</p>
        </div>
    </div>
</body>
</html>
EOF
    fi
fi

# Display VPN configurations in dialog with instructions
dialog --msgbox "OpenVPN is set up! Below is the configuration file (client.ovpn) needed to connect to your VPN.\nSave this file or copy its contents to your VPN client (e.g., OpenVPN Connect)." 10 60
dialog --title "OpenVPN Client Config" --textbox "$client_config" 20 70

if [ $deploy_wireguard -eq 1 ]; then
    dialog --msgbox "WireGuard is set up! Below is the configuration file (wg-client.conf) needed to connect to your VPN.\nSave this file or copy its contents to your WireGuard client app." 10 60
    echo "$wireguard_config" > /tmp/wg-client.conf
    dialog --title "WireGuard Client Config" --textbox /tmp/wg-client.conf 20 70
    rm -f /tmp/wg-client.conf
fi

# Display web deployment messages
if [ $deploy_openvpn_web -eq 1 ]; then
    dialog --msgbox "OpenVPN website deployed at http://$server_ip/openvpn.html.\nDownload client.ovpn or scan the QR code from the webpage." 10 60
fi

if [ $deploy_wireguard -eq 1 ]; then
    dialog --msgbox "WireGuard website deployed at http://$server_ip/wireguard.html.\nDownload wg-client.conf or scan the QR code from the webpage." 10 60
fi

# Prompt to remove webpages for security
if [ $deployed_web -eq 1 ]; then
    dialog --yesno "Would you like to remove the webpages for security purposes (to avoid sharing with others)?" 10 50
    if [ $? -eq 0 ]; then
        rm -rf /var/www/vpn
        rm -f /etc/nginx/sites-available/vpn-site /etc/nginx/sites-enabled/vpn-site
        systemctl restart nginx
        ufw delete allow 80/tcp
        ufw delete allow 443/tcp
        dialog --msgbox "Webpages removed successfully. HTTP/HTTPS ports closed in UFW." 10 40
    fi
fi

# Prompt for server hardening with LUKS encryption
dialog --yesno "Would you like to harden your VPN/VPS server with disk encryption using LUKS?" 10 50
if [ $? -eq 0 ]; then
    apt install -y cryptsetup || error_exit "Failed to install cryptsetup."
    
    dialog --msgbox "Disk encryption setup instructions:\n\nWARNING: Encrypting the root partition on a running system can lead to data loss. Use a non-root partition or a live USB for safety.\n\nSteps to encrypt a data partition (e.g., /dev/sdb1):\n1. Identify a partition with 'lsblk' or 'fdisk -l'. Ensure it's not mounted.\n2. Run: cryptsetup luksFormat /dev/sdb1 (set a strong passphrase).\n3. Open the encrypted device: cryptsetup luksOpen /dev/sdb1 encrypted\n4. Create a filesystem: mkfs.ext4 /dev/mapper/encrypted\n5. Mount it: mkdir /mnt/encrypted && mount /dev/mapper/encrypted /mnt/encrypted\n6. For auto-mount, add to /etc/crypttab and /etc/fstab (use UUID).\n\nPassphrase: You'll use the passphrase set in step 2 to unlock the device.\nYou can move VPN configs to the encrypted partition for added security.\n\nOpen another terminal to run these commands manually." 20 70
fi

# Prompt for Suricata and CrowdSec installation
dialog --yesno "Would you like to install Suricata and CrowdSec?\n\nBenefits: CrowdSec detects and blocks malicious IPs collaboratively. Suricata inspects network traffic for threats.\n\nWARNING: These tools may impact performance on low-end hardware (e.g., low CPU/RAM VPS)." 15 60
if [ $? -eq 0 ]; then
    # Install CrowdSec
    dialog --msgbox "Installing CrowdSec..." 10 40
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash || error_exit "Failed to configure CrowdSec repository."
    apt install -y crowdsec || error_exit "Failed to install CrowdSec."
    systemctl enable crowdsec
    systemctl start crowdsec
    dialog --msgbox "CrowdSec installed and started." 10 40
    
    # Install Suricata dependencies
    dialog --msgbox "Installing Suricata 8 dependencies..." 10 40
    # Explicitly install libpcre2-dev first
    if ! apt install -y libpcre2-dev; then
        error_exit "Failed to install libpcre2-dev. Run 'apt update' and 'apt install libpcre2-dev' manually."
    fi
    # Check for pcre2 library
    if ! pkg-config --libs --cflags libpcre2-8; then
        error_exit "libpcre2-8 not found. Run 'apt install libpcre2-dev' manually and check /tmp/suricata-configure.log."
    fi
    DEPS="build-essential autoconf automake libtool libpcap-dev libnet1-dev libyaml-dev libjansson-dev zlib1g-dev libmagic-dev libcap-ng-dev libevent-dev liblua5.1-0-dev libhiredis-dev libmaxminddb-dev liblz4-dev python3-yaml jq libpcre3-dev libpcre2-8-0"
    for dep in $DEPS; do
        if ! apt install -y $dep; then
            error_exit "Failed to install dependency: $dep"
        fi
    done
    dialog --msgbox "Suricata dependencies installed successfully." 10 40
    
    # Install Rust and cbindgen for Suricata
    dialog --msgbox "Installing Rust and cbindgen for Suricata..." 10 40
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y || error_exit "Failed to install Rust."
    source $HOME/.cargo/env
    cargo install --force cbindgen || error_exit "Failed to install cbindgen."
    
    # Build Suricata 8 from source
    dialog --msgbox "Building Suricata 8 from source..." 10 40
    cd /tmp
    wget https://www.openinfosecfoundation.org/download/suricata-8.0.0.tar.gz || error_exit "Failed to download Suricata source."
    tar -xzvf suricata-8.0.0.tar.gz
    cd suricata-8.0.0
    ./configure --enable-af-packet --prefix=/usr --sysconfdir=/etc --localstatedir=/var > /tmp/suricata-configure.log 2>&1 || {
        dialog --title "Suricata Configure Error" --textbox /tmp/suricata-configure.log 20 70
        error_exit "Suricata configuration failed. Check /tmp/suricata-configure.log for details. Try installing missing dependencies manually (e.g., apt install libpcre2-dev)."
    }
    make -j$(nproc) || error_exit "Suricata compilation failed."
    make install || error_exit "Suricata installation failed."
    make install-conf || error_exit "Suricata install-conf failed."
    cd -
    rm -rf /tmp/suricata-8.0.0 /tmp/suricata-8.0.0.tar.gz
    
    # Check system RAM
    total_ram=$(free -m | grep "Mem:" | awk '{print $2}')
    if [ "$total_ram" -lt 2048 ]; then
        dialog --yesno "Your system has less than 2GB RAM ($total_ram MB). Would you like to limit Suricata's RAM and CPU usage to prevent restart loops?\n\nThis will set max-pending-packets to 1024 and enable auto CPU affinity." 15 60
        if [ $? -eq 0 ]; then
            sed -i "/^af-packet:/a\  - max-pending-packets: 1024" /etc/suricata/suricata.yaml
            sed -i "/^af-packet:/a\  - cpu-affinity: auto" /etc/suricata/suricata.yaml
            if ! python3 -c "import yaml; yaml.safe_load(open('/etc/suricata/suricata.yaml'))" 2>/dev/null; then
                dialog --msgbox "Invalid YAML syntax after RAM/CPU limit changes. Restoring backup." 10 40
                cp /etc/suricata/suricata.yaml.bak /etc/suricata/suricata.yaml
                error_exit "Suricata RAM/CPU configuration invalid."
            fi
            dialog --msgbox "Suricata configured with limited RAM (max-pending-packets: 1024) and auto CPU affinity." 10 50
        fi
    fi
    
    # Configure Suricata with af-packet
    dialog --msgbox "Configuring Suricata with af-packet..." 10 40
    cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak
    # Ensure af-packet section is correctly configured
    if ! grep -q "^af-packet:" /etc/suricata/suricata.yaml; then
        echo -e "\naf-packet:\n  - interface: $interface\n    cluster-id: 99\n    cluster-type: cluster_flow\n    defrag: yes" >> /etc/suricata/suricata.yaml
    else
        sed -i "/^af-packet:/,/^[^ ]/s|^  - interface:.*|  - interface: $interface\n    cluster-id: 99\n    cluster-type: cluster_flow\n    defrag: yes|" /etc/suricata/suricata.yaml
    fi
    sed -i "s|HOME_NET:.*|HOME_NET: \"[$server_ip/32]\"|" /etc/suricata/suricata.yaml
    sed -i "s/community-id: false/community-id: true/" /etc/suricata/suricata.yaml
    
    # Validate YAML
    if ! python3 -c "import yaml; yaml.safe_load(open('/etc/suricata/suricata.yaml'))" 2>/dev/null; then
        dialog --msgbox "Invalid YAML syntax in /etc/suricata/suricata.yaml. Restoring backup." 10 40
        cp /etc/suricata/suricata.yaml.bak /etc/suricata/suricata.yaml
        error_exit "Suricata configuration invalid."
    fi
    
    # Update Suricata rules
    dialog --msgbox "Updating Suricata rules..." 10 40
    suricata-update || error_exit "Failed to update Suricata rules."
    
    # Test Suricata configuration
    if ! suricata -T -c /etc/suricata/suricata.yaml -v; then
        dialog --msgbox "Suricata configuration test failed. Check /etc/suricata/suricata.yaml and logs in /var/log/suricata/." 10 50
        cp /etc/suricata/suricata.yaml.bak /etc/suricata/suricata.yaml
        error_exit "Suricata configuration test failed."
    fi
    
    # Prompt for IPS mode with af-packet
    dialog --yesno "Would you like to enable Suricata IPS mode using af-packet on interface $interface?\n\nIPS mode allows Suricata to drop malicious packets but requires proper network setup (e.g., bridge or iptables routing)." 15 60
    if [ $? -eq 0 ]; then
        # Configure af-packet for IPS mode
        sed -i "/^af-packet:/,/^[^ ]/s|^  - interface:.*|  - interface: $interface\n    cluster-id: 99\n    cluster-type: cluster_flow\n    defrag: yes\n    copy-mode: ips\n    copy-iface: $interface|" /etc/suricata/suricata.yaml
        if ! python3 -c "import yaml; yaml.safe_load(open('/etc/suricata/suricata.yaml'))" 2>/dev/null; then
            dialog --msgbox "Invalid YAML syntax in /etc/suricata/suricata.yaml after IPS mode changes. Restoring backup." 10 40
            cp /etc/suricata/suricata.yaml.bak /etc/suricata/suricata.yaml
            error_exit "Suricata IPS configuration invalid."
        fi
        dialog --msgbox "Suricata configured for IPS mode with af-packet. For full IPS functionality, ensure network traffic is routed through Suricata (e.g., using iptables or a bridge).\nExample iptables rule: iptables -A FORWARD -i $interface -j DROP\nRestart Suricata: systemctl restart suricata" 10 60
    fi
    
    # Create Suricata systemd service
    cat > /etc/systemd/system/suricata.service << EOF
[Unit]
Description=Suricata Intrusion Detection and Prevention
After=network.target

[Service]
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -i $interface --pidfile /var/run/suricata.pid
ExecReload=/bin/kill -HUP \$MAINPID
PIDFile=/var/run/suricata.pid
Restart=always
Type=simple

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable suricata
    systemctl start suricata
    
    # Prompt for logging and detection test
    dialog --yesno "Would you like to test Suricata logging and detection?\nThis will use curl to access testmyids.com and check fast.log and eve.json." 10 50
    if [ $? -eq 0 ]; then
        curl -s http://testmyids.com > /dev/null
        sleep 5  # Allow time for logs to update
        fast_log="/var/log/suricata/fast.log"
        eve_json="/var/log/suricata/eve.json"
        if [ -f "$fast_log" ] && [ -s "$fast_log" ] && [ -f "$eve_json" ] && [ -s "$eve_json" ]; then
            dialog --msgbox "Logging and IPS mode test successful!\nfast.log and eve.json contain entries, indicating Suricata is logging and detecting traffic." 10 60
        else
            dialog --msgbox "Logging and IPS mode test failed.\nCheck fast.log and eve.json in /var/log/suricata/ for entries or ensure Suricata is running (systemctl status suricata)." 10 60
        fi
    fi
    dialog --msgbox "Suricata and CrowdSec installed and configured.\nSuricata is running in $([ $? -eq 0 ] && echo 'IPS mode with af-packet' || echo 'IDS mode').\nCheck logs in /var/log/suricata/ if issues arise." 10 50
fi

# Final message
dialog --msgbox "Setup complete! OpenVPN and optional WireGuard are configured.\nCheck the dialog outputs above for client configurations or visit the web pages (if deployed) for easy access." 10 60

# Clean up
rm -f /tmp/openvpn-install.sh /tmp/suricata-configure.log