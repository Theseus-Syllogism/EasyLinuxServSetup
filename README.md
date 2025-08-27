# OpenVPN and Wireguard VPN Server with QR Code/Frontend for Easy Configuration

## VPN Script

##### This script detects the public facing network interface, appends changes to OpenVPN and Wireguard, installs Nginx and deploys a webpage over HTTP at the server's IP address (revised scripts will support HTTPS and domains for HTTPS Camoflauge and Obsfucation) It is recommended to remove the webpage if deployed after client configuration, which can be done by a prompt or by disabling nginx and/or removing entries in the /var/www/ directory. The purpose of this script is to allow for easy-deployments of VPN server's on VPS servers or homelab servers.

### Other Features
- LUKS install instructions (work in progress)
- CrowdSec/Suricata install (work in progress)

#### Current Support
- Debian 11/12
- Ubuntu 24 (untested)

# Current Options
![Imgur Image](https://i.imgur.com/PjegZOL.png)
![Imgur Image](https://i.imgur.com/RRk2GrQ.png)
![Imgur Image](https://i.imgur.com/piYyeBm.png)
![Imgur Image](https://i.imgur.com/FHUPsI6.png)

# EzLinuxSetup.sh 
#### This script is focused on providing a hassle-free deployment to Debian servers, installing nginx, certbot and dependencies, as well as prompting for SSL certification for the domain name then utilizing certbot -d --nginx [domainname], additionally it'll prompt for a Suricata and CrowdSec, then installing Rust and compiling Suricata 8 from source. An optional prompt asks for IPS configuration (work in progress) and creating a suricata.service file

#### Issues
- Suricata IPS configures in af-packet mode -> change to nfq mode with sed insertions to suricata.yaml and change ./configure options
- certbot can occasionally fail without an .acme stand in in the /sites-available/ file, however given the file created only includes an HTTP server block by default this is usually not a problem found in testing, additionally certbot will automatically generate an HTTPS block. sed -i for HTTPs block may best be removed


