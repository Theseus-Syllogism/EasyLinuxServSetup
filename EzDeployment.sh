#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

print_header() {
    echo -e "\n${GREEN}=== $1 ===${NC}"
}

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}" 
   exit 1
fi

print_header "Checking Operating System"
if ! grep -Ei '^(ID|ID_LIKE)=(.*debian.*|.*ubuntu.*)' /etc/os-release > /dev/null; then
    echo -e "${RED}This script is designed for Debian or Ubuntu systems only${NC}"
    echo -e "${RED}Contents of /etc/os-release:${NC}"
    cat /etc/os-release
    exit 1
else
    echo -e "${GREEN}Detected Debian or Ubuntu system${NC}"
fi

print_header "Updating System"
apt update && apt upgrade -y

print_header "Installing Required Packages"
apt install -y nginx certbot python3 python3-certbot-nginx nano ufw curl wget git vim sudo

print_header "Configuring Firewall (UFW)"
ufw allow ssh
ufw allow 'Nginx Full'
ufw --force enable
echo -e "${GREEN}Firewall configured to allow SSH, HTTP, and HTTPS${NC}"

print_header "Disable Root SSH Login"
echo "Would you like to disable root login via SSH for enhanced security? (y/n)"
read -p "Choice: " ROOT_LOGIN_CHOICE
if [[ "$ROOT_LOGIN_CHOICE" =~ ^[Yy]$ ]]; then
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    systemctl restart sshd
    echo -e "${GREEN}Root SSH login disabled. Use a non-root user with sudo privileges for SSH access.${NC}"
fi

print_header "Nginx Configuration"
echo "Please enter your domain name (e.g., example.com):"
read -p "Domain: " DOMAIN
if [[ -z "$DOMAIN" ]]; then
    echo -e "${RED}Domain name cannot be empty${NC}"
    exit 1
fi

cat > /etc/nginx/sites-available/$DOMAIN << EOF
server {
    listen 80;
    server_name $DOMAIN www.$DOMAIN;
    root /var/www/$DOMAIN/html;
    index index.html index.htm;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

mkdir -p /var/www/$DOMAIN/html
chown -R www-data:www-data /var/www/$DOMAIN/html
chmod -R 755 /var/www/$DOMAIN/html


ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
echo -e "${GREEN}Nginx configured for $DOMAIN${NC}"

print_header "Setting up SSL with Certbot"
echo "Would you like to enable SSL via Certbot for $DOMAIN? (y/n)"
read -p "Choice: " CERTBOT_CHOICE
if [[ "$CERTBOT_CHOICE" =~ ^[Yy]$ ]]; then
    # nginx and certbot deployment will often fail without an .acme stand in
    sed -i "/location \/ {/i location /.well-known/acme-challenge/ {\n root /var/www/html;\n allow all;\n}" /etc/nginx/sites-available/$DOMAIN
    nginx -t && systemctl reload nginx

    certbot certonly --nginx -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos --email admin@$DOMAIN || {
        echo -e "${RED}Certbot setup failed. Please check your domain DNS settings and try running 'certbot --nginx' manually.${NC}"
    }
    cat >> /etc/nginx/sites-available/$DOMAIN << EOF

server {
    listen 443 ssl;
    server_name $DOMAIN www.$DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    root /var/www/$DOMAIN/html;
    index index.html index.htm;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

    # Redirect HTTP to HTTPS
    sed -i '/listen 80;/a\    return 301 https://\$server_name\$request_uri;' /etc/nginx/sites-available/$DOMAIN

    nginx -t && systemctl reload nginx
    echo -e "${GREEN}SSL certificate added and Nginx configuration updated for $DOMAIN${NC}"
    echo "Test SSL: curl -I https://$DOMAIN"
fi

print_header "Creating Sample Web Page"
cat > /var/www/$DOMAIN/html/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to $DOMAIN</title>
</head>
<body>
    <h1>Welcome to your new website on $DOMAIN!</h1>
    <p>This is a sample page. You can edit it in /var/www/$DOMAIN/html/index.html</p>
</body>
</html>
EOF
chown www-data:www-data /var/www/$DOMAIN/html/index.html
echo -e "${GREEN}Sample web page created at /var/www/$DOMAIN/html/index.html${NC}"

print_header "Retrieving Server IP Address"
IPV4=$(curl -s -4 ifconfig.me 2>/dev/null)

if [[ -z "$IPV4" ]]; then
    IPV6=$(curl -s -6 ifconfig.me 2>/dev/null)
    if [[ -z "$IPV6" ]]; then
        echo -e "${RED}Could not retrieve public IP address. Please check your network configuration.${NC}"
        IP_ADDRESS="your-server-ip"
    else
        IP_ADDRESS=$IPV6
        echo -e "${GREEN}Public IPv6 address: $IP_ADDRESS${NC}"
    fi
else
    IP_ADDRESS=$IPV4
    echo -e "${GREEN}Public IPv4 address: $IP_ADDRESS${NC}"
fi

print_header "Additional Security Setup"
echo "Would you like to install additional security tools (Suricata 8 and CrowdSec)? (y/n)"
read -p "Choice: " SECURITY_CHOICE
if [[ "$SECURITY_CHOICE" =~ ^[Yy]$ ]]; then
    print_header "Installing Rust for Suricata"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
    # Install cbindgen for Suricata
    cargo install --force cbindgen
    echo -e "${GREEN}Rust and cbindgen installed${NC}"

    print_header "Installing Suricata 8 Dependencies"
    DEPS="build-essential gcc autoconf automake libtool libpcap-dev libnet1-dev \
          libyaml-dev libjansson-dev zlib1g-dev libmagic-dev libcap-ng-dev \
          libevent-dev liblua5.1-0-dev libhiredis-dev libmaxminddb-dev liblz4-dev \
          python3-yaml jq libnetfilter-queue-dev libnetfilter-queue1 \
          libnfnetlink-dev libnfnetlink0 libpcre2-dev"

    if ! apt install -y $DEPS; then
        echo -e "${RED}Failed to install Suricata dependencies. Please ensure the package names are correct for your system (e.g., 'libpcre2-dev' on Debian).${NC}"
        echo "Try installing manually: apt install -y $DEPS"
        exit 1
    fi
    echo -e "${GREEN}Suricata dependencies installed${NC}"

    print_header "Building Suricata 8 from Source"
    wget https://www.openinfosecfoundation.org/download/suricata-8.0.0.tar.gz -P /tmp || {
        echo -e "${RED}Failed to download Suricata source. Check your internet connection or the URL.${NC}"
        exit 1
    }
    tar -xzvf /tmp/suricata-8.0.0.tar.gz -C /tmp
    cd /tmp/suricata-8.0.0
    # Configure with NFQUEUE support for IPS mode
    ./configure --enable-nfqueue --prefix=/usr --sysconfdir=/etc --localstatedir=/var || {
        echo -e "${RED}Suricata configuration failed. Please check dependencies and try again.${NC}"
        exit 1
    }
    make -j8 || {
        echo -e "${RED}Suricata compilation failed. Please check the output for errors.${NC}"
        exit 1
    }
    make install || {
        echo -e "${RED}Suricata installation failed. Please check the output for errors.${NC}"
        exit 1
    }
    cd -
    rm -rf /tmp/suricata-8.0.0 /tmp/suricata-8.0.0.tar.gz
    echo -e "${GREEN}Suricata 8 built and installed from source${NC}"

    print_header "Detecting Public-Facing Network Interface"
    INTERFACE=$(ip route show default | grep -oP 'dev \K\S+')
    if [[ -z "$INTERFACE" ]]; then
        echo -e "${RED}No public-facing interface detected, defaulting to eth0${NC}"
        INTERFACE="eth0"
    else
        echo -e "${GREEN}Detected public-facing interface: $INTERFACE${NC}"
    fi

    print_header "Configuring Suricata"
    cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak
    sed -i "/^af-packet:/,/^  - interface:/s/  - interface: eth0/  - interface: $INTERFACE/" /etc/suricata/suricata.yaml
    # Set HOME_NET to the server's IP
    if [[ -n "$IPV4" ]]; then
        sed -i "s/HOME_NET: \"\[192.168.0.0\/16,10.0.0.0\/8,172.16.0.0\/12\]\"/HOME_NET: \"[$IPV4\/32]\"/" /etc/suricata/suricata.yaml
    elif [[ -n "$IPV6" ]]; then
        sed -i "s/HOME_NET: \"\[192.168.0.0\/16,10.0.0.0\/8,172.16.0.0\/12\]\"/HOME_NET: \"[$IPV6\/128]\"/" /etc/suricata/suricata.yaml
    fi
    # Enable community-id
    sed -i "s/community-id: false/community-id: true/" /etc/suricata/suricata.yaml
    # Validate YAML syntax
    if ! python3 -c "import yaml; yaml.safe_load(open('/etc/suricata/suricata.yaml'))"; then
        echo -e "${RED}Invalid YAML syntax in /etc/suricata/suricata.yaml. Restoring backup.${NC}"
        cp /etc/suricata/suricata.yaml.bak /etc/suricata/suricata.yaml
        exit 1
    fi
    echo -e "${GREEN}Suricata configuration updated${NC}"

    print_header "Hardening Suricata (IPS Mode)"
    echo "Would you like to harden Suricata by enabling IPS mode? This allows Suricata to drop malicious packets (y/n)"
    read -p "Choice: " IPS_CHOICE
    if [[ "$IPS_CHOICE" =~ ^[Yy]$ ]]; then
        # Configure Suricata for IPS mode using NFQUEUE
        sed -i "s/af-packet:/nfqueue:/" /etc/suricata/suricata.yaml
        sed -i "/^nfqueue:/a\  - interface: $INTERFACE\n    queue: 0" /etc/suricata/suricata.yaml
        # Validate YAML syntax again
        if ! python3 -c "import yaml; yaml.safe_load(open('/etc/suricata/suricata.yaml'))"; then
            echo -e "${RED}Invalid YAML syntax in /etc/suricata/suricata.yaml after IPS mode changes. Restoring backup.${NC}"
            cp /etc/suricata/suricata.yaml.bak /etc/suricata/suricata.yaml
            exit 1
        fi
        echo -e "${GREEN}Suricata configured for IPS mode (NFQUEUE settings applied). iptables rules deferred until after Suricata setup.${NC}"
    fi

    print_header "Installing Suricata Rules"
    suricata-update || {
        echo -e "${RED}Failed to update Suricata rules. Check /etc/suricata/suricata.yaml or run 'suricata-update' manually.${NC}"
        exit 1
    }
    echo -e "${GREEN}Suricata rules updated${NC}"

    print_header "Checking Suricata Configuration"
    if suricata -T -c /etc/suricata/suricata.yaml -v; then
        echo -e "${GREEN}Suricata configuration test passed${NC}"
    else
        echo -e "${RED}Suricata configuration test failed. Please check /etc/suricata/suricata.yaml${NC}"
        exit 1
    fi

    print_header "Enabling and Starting Suricata"
    # Create systemd service file for Suricata
    cat > /etc/systemd/system/suricata.service << EOF
[Unit]
Description=Suricata Intrusion Detection and Prevention
After=network.target

[Service]
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -i $INTERFACE --pidfile /var/run/suricata.pid
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

systemctl status suricata --no-pager

echo -e "${GREEN}Suricata enabled and running${NC}"

    # Deferred IPS mode iptables setup
    if [[ "$IPS_CHOICE" =~ ^[Yy]$ ]]; then
        print_header "Configuring IPS Mode iptables Rules"
        # Install required packages for IPS mode
        apt install -y iptables
        # Load nfnetlink_queue kernel module
        modprobe nfnetlink_queue || {
            echo -e "${RED}Failed to load nfnetlink_queue module. IPS mode requires this module.${NC}"
            echo "Try loading manually: modprobe nfnetlink_queue"
            exit 1
        }
        # Set up iptables to direct traffic to Suricata's NFQUEUE
        if [[ -n "$IPV4" ]]; then
            iptables -I INPUT -j NFQUEUE --queue-num 0
            iptables -I OUTPUT -j NFQUEUE --queue-num 0
            iptables -I FORWARD -j NFQUEUE --queue-num 0
            iptables-save > /etc/iptables/rules.v4
        fi
        if [[ -n "$IPV6" ]]; then
            ip6tables -I INPUT -j NFQUEUE --queue-num 0
            ip6tables -I OUTPUT -j NFQUEUE --queue-num 0
            ip6tables -I FORWARD -j NFQUEUE --queue-num 0
            ip6tables-save > /etc/iptables/rules.v6
        fi
        # Install netfilter-persistent and configure non-interactively
        echo "netfilter-persistent netfilter-persistent/autosave_v4 boolean true" | debconf-set-selections
        echo "netfilter-persistent netfilter-persistent/autosave_v6 boolean true" | debconf-set-selections
        apt install -y netfilter-persistent || {
            echo -e "${RED}Failed to install netfilter-persistent. Rules saved manually to /etc/iptables/rules.v[4,6].${NC}"
            echo "To persist rules, install netfilter-persistent manually: apt install -y netfilter-persistent"
        }
        echo -e "${GREEN}IPS mode iptables rules configured and saved${NC}"
    fi

    print_header "Installing CrowdSec"
    # Install CrowdSec
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
    apt install -y crowdsec
    # Install CrowdSec Nginx bouncer
    apt install -y crowdsec-nginx-bouncer

    print_header "Configuring CrowdSec"
    # Configure CrowdSec to monitor Nginx logs
    cscli collections install crowdsecurity/nginx
    cscli parsers install crowdsecurity/whitelists
    # Enable and start CrowdSec
    systemctl enable crowdsec
    systemctl start crowdsec
    systemctl status crowdsec --no-pager
    echo -e "${GREEN}CrowdSec enabled and running${NC}"
fi

print_header "Email Server Setup"
echo "Would you like to install an email server (Postfix, Dovecot, SpamAssassin) for $DOMAIN? (y/n)"
read -p "Choice: " EMAIL_CHOICE
if [[ "$EMAIL_CHOICE" =~ ^[Yy]$ ]]; then #note ^ in [Yy]
    print_header "Installing Email Server"
    # Download and run the mail server setup script
    wget https://raw.githubusercontent.com/maikka39/MailServerSetup/master/setup_mail_server.sh -O /tmp/setup_mail_server.sh
    chmod +x /tmp/setup_mail_server.sh
    # Run the mail server setup script with the provided domain
    /tmp/setup_mail_server.sh $DOMAIN || {
        echo -e "${RED}Email server setup failed. Please check the script output or run '/tmp/setup_mail_server.sh $DOMAIN' manually.${NC}"
        exit 1
    }
    rm -f /tmp/setup_mail_server.sh
    echo -e "${GREEN}Email server installed and configured for $DOMAIN${NC}"
    # Update UFW for email ports
    ufw allow 25   # SMTP
    ufw allow 587  # Submission
    ufw allow 143  # IMAP
    ufw allow 993  # IMAPS
    echo -e "${GREEN}Firewall updated to allow email ports (25, 587, 143, 993)${NC}"
fi

print_header "Nextcloud File Server Setup"
echo "Would you like to install Nextcloud as a file server (similar to Dropbox) for $DOMAIN? (y/n)"
read -p "Choice: " NEXTCLOUD_CHOICE
if [[ "$NEXTCLOUD_CHOICE" =~ ^[Yy]$ ]]; then
    print_header "Installing Nextcloud Dependencies"
    apt install -y apache2 mariadb-server php php-mysql php-gd php-json php-curl php-mbstring php-intl php-imagick php-xml php-zip unzip
    # Secure MariaDB installation
    mysql_secure_installation <<EOF

y
n
y
y
y
y
EOF
    # Create Nextcloud database and user
    DB_USER="nextcloud"
    DB_PASS=$(openssl rand -base64 12)
    DB_NAME="nextcloud"
    mysql -u root -e "CREATE DATABASE $DB_NAME; GRANT ALL ON $DB_NAME.* TO '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS'; FLUSH PRIVILEGES;"
    echo -e "${GREEN}Nextcloud database created (user: $DB_USER, password: $DB_PASS)${NC}"

    print_header "Installing Nextcloud"
    wget https://download.nextcloud.com/server/releases/latest.zip -P /tmp
    unzip /tmp/latest.zip -d /var/www/
    chown -R www-data:www-data /var/www/nextcloud
    chmod -R 755 /var/www/nextcloud
    rm -f /tmp/latest.zip

    # Configure Apache for Nextcloud
    cat > /etc/apache2/sites-available/nextcloud.conf << EOF
<VirtualHost *:80>
    ServerName $DOMAIN
    DocumentRoot /var/www/nextcloud
    <Directory /var/www/nextcloud/>
        Options +FollowSymlinks
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog \${APACHE_LOG_DIR}/nextcloud_error.log
    CustomLog \${APACHE_LOG_DIR}/nextcloud_access.log combined
</VirtualHost>
EOF
    a2ensite nextcloud.conf
    a2enmod rewrite headers env dir mime
    systemctl restart apache2
    echo -e "${GREEN}Nextcloud installed and Apache configured for $DOMAIN${NC}"
    echo "Complete the Nextcloud setup by visiting http://$DOMAIN and using the database credentials:"
    echo "Database user: $DB_USER"
    echo "Database password: $DB_PASS"
    echo "Database name: $DB_NAME"
    echo "Host: localhost"
fi

print_header "Setup Complete"
echo "Your server is now configured with:"
echo "- Nginx web server"
echo "- Basic firewall (UFW)"
echo "- Basic utilities (nano, curl, wget, git)"
if [[ "$ROOT_LOGIN_CHOICE" =~ ^[Yy]$ ]]; then
    echo "- Root SSH login disabled"
fi
if [[ "$SECURITY_CHOICE" =~ ^[Yy]$ ]]; then
    echo "- Suricata 8 ($( [[ "$IPS_CHOICE" =~ ^[Yy]$ ]] && echo "IPS mode (iptables rules deferred)" || echo "IDS mode" ))"
    echo "- CrowdSec (security engine)"
fi
if [[ "$EMAIL_CHOICE" =~ ^[Yy]$ ]]; then
    echo "- Email server (Postfix, Dovecot, SpamAssassin)"
fi
if [[ "$NEXTCLOUD_CHOICE" =~ ^[Yy]$ ]]; then
    echo "- Nextcloud file server"
fi
echo "You can edit your website files in /var/www/$DOMAIN/html/"
echo "To modify Nginx configuration, edit /etc/nginx/sites-available/$DOMAIN"
echo "To manage your SSL certificate, use 'certbot renew' or 'certbot')"
if [[ "$SECURITY_CHOICE" =~ ^[Yy]$ ]]; then
    echo "To manage Suricata, edit /etc/suricata/suricata.yaml or use 'suricata-update' for rules"
    echo "To manage CrowdSec, use 'cscli' commands (e.g., 'cscli dashboard' for metrics)"
    if [[ "$IPS_CHOICE" =~ ^[Yy]$ ]]; then
        echo "To fully enable Suricata IPS mode, ensure iptables and netfilter-persistent are installed and rules are applied (now deferred)."
        echo "Run: apt install -y iptables netfilter-persistent"
        echo "Check rules: cat /etc/iptables/rules.v[4,6]"
    fi
fi
if [[ "$EMAIL_CHOICE" =~ ^[Yy]$ ]]; then
    echo "To manage the email server, check Postfix and Dovecot configurations in /etc/postfix/ and /etc/dovecot/"
fi
if [[ "$NEXTCLOUD_CHOICE" =~ ^[Yy]$ ]]; then
    echo "To complete Nextcloud setup, visit http://$DOMAIN and use the provided database credentials."
    echo "To manage Nextcloud, edit /var/www/nextcloud/config/config.php"
fi
echo -e "${GREEN}Visit http://$IP_ADDRESS to see your site!${NC}"
echo -e "\n${GREEN}Linking Your Domain to the IP Address:${NC}"
echo "To link your domain ($DOMAIN) to this server, update your domain's DNS settings at your registrar (e.g., GoDaddy, Namecheap):"
echo "1. Log in to your domain registrar's control panel."
echo "2. Find the DNS management or nameserver settings for $DOMAIN."
echo "3. Add or update an A record (for IPv4) or AAAA record (for IPv6):"
if [[ -n "$IPV4" ]]; then
    echo "   - Type: A, Name: @, Value: $IPV4, TTL: 3600 (or default)"
fi
if [[ -n "$IPV6" ]]; then
    echo "   - Type: AAAA, Name: @, Value: $IPV6, TTL: 3600 (or default)"
fi
echo "4. Save changes and allow 1-24 hours for DNS propagation."
echo "5. Once propagated, visit http://$DOMAIN to see your site."
echo -e "${GREEN}Note: If you haven't pointed your domain's DNS yet, you can test your site by visiting http://$IP_ADDRESS${NC}"