#!/bin/bash

# BIND DNS Server Installation and Configuration Script
# This script checks for BIND installation, installs if needed, and helps configure basic DNS settings

# Text colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Please run this script as root or with sudo.${NC}"
        exit 1
    fi
}

# Function to detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
        echo -e "${CYAN}Detected OS: $OS $VERSION${NC}"
    else
        echo -e "${RED}Unable to detect OS. This script supports Ubuntu, Debian, CentOS, and RHEL.${NC}"
        exit 1
    fi
}

# Function to check if BIND is installed
check_bind_installed() {
    echo -e "${CYAN}Checking if BIND is installed...${NC}"
    
    case $OS in
        ubuntu|debian)
            if dpkg -l | grep -q "^ii.*bind9 "; then
                echo -e "${GREEN}BIND is already installed.${NC}"
                return 0
            else
                echo -e "${YELLOW}BIND is not installed.${NC}"
                return 1
            fi
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if rpm -q bind &>/dev/null; then
                echo -e "${GREEN}BIND is already installed.${NC}"
                return 0
            else
                echo -e "${YELLOW}BIND is not installed.${NC}"
                return 1
            fi
            ;;
        *)
            echo -e "${RED}Unsupported OS for automated BIND check.${NC}"
            exit 1
            ;;
    esac
}

# Function to install BIND
install_bind() {
    echo -e "${CYAN}Installing BIND DNS server...${NC}"
    
    case $OS in
        ubuntu|debian)
            apt-get update
            apt-get install -y bind9 bind9utils bind9-doc
            systemctl enable named
            systemctl start named
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if [ "$OS" == "centos" ] && [ "$VERSION" -lt 8 ]; then
                yum install -y bind bind-utils
            else
                dnf install -y bind bind-utils
            fi
            systemctl enable named
            systemctl start named
            ;;
        *)
            echo -e "${RED}Unsupported OS for automated BIND installation.${NC}"
            exit 1
            ;;
    esac
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}BIND DNS server installed successfully.${NC}"
    else
        echo -e "${RED}Failed to install BIND DNS server.${NC}"
        exit 1
    fi
}

# Function to determine BIND configuration paths
get_bind_paths() {
    case $OS in
        ubuntu|debian)
            BIND_CONFIG_DIR="/etc/bind"
            BIND_CONFIG_FILE="$BIND_CONFIG_DIR/named.conf"
            ZONES_DIR="$BIND_CONFIG_DIR/zones"
            NAMED_SERVICE="named"
            ;;
        centos|rhel|fedora|rocky|almalinux)
            BIND_CONFIG_DIR="/etc"
            BIND_CONFIG_FILE="$BIND_CONFIG_DIR/named.conf"
            ZONES_DIR="/var/named"
            NAMED_SERVICE="named"
            ;;
        *)
            echo -e "${RED}Unsupported OS for BIND configuration.${NC}"
            exit 1
            ;;
    esac
    
    # Create zones directory if it doesn't exist
    mkdir -p $ZONES_DIR 2>/dev/null
}

# Function to configure BIND (basic settings)
configure_bind_basic() {
    echo -e "${CYAN}Configuring BIND basic settings...${NC}"
    
    # Backup original configuration
    if [ -f "$BIND_CONFIG_FILE" ]; then
        cp "$BIND_CONFIG_FILE" "$BIND_CONFIG_FILE.bak.$(date +%Y%m%d%H%M%S)"
        echo -e "${GREEN}Backed up original configuration.${NC}"
    fi
    
    # Create named.conf options section with more secure defaults
    cat > "$BIND_CONFIG_DIR/named.conf.options" << EOF
options {
    directory "/var/cache/bind";
    
    recursion yes;
    allow-recursion { localhost; 10.0.0.0/8; 172.16.0.0/12; 192.168.0.0/16; };
    
    // Forwarding configuration - change these to your preferred DNS servers
    forwarders {
        1.1.1.1;
        8.8.8.8;
    };
    
    dnssec-validation auto;
    
    listen-on { any; };
    listen-on-v6 { any; };
    
    // Query restrictions
    allow-query { localhost; 10.0.0.0/8; 172.16.0.0/12; 192.168.0.0/16; };
    
    // Transfer restrictions
    allow-transfer { none; };
    
    // Version hiding for security
    version "not disclosed";
};
EOF

    # Update main config to include our options
    case $OS in
        ubuntu|debian)
            if ! grep -q "named.conf.options" "$BIND_CONFIG_FILE"; then
                echo 'include "/etc/bind/named.conf.options";' >> "$BIND_CONFIG_FILE"
            fi
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if [ ! -f "$BIND_CONFIG_FILE" ]; then
                cat > "$BIND_CONFIG_FILE" << EOF
include "$BIND_CONFIG_DIR/named.conf.options";
EOF
            elif ! grep -q "named.conf.options" "$BIND_CONFIG_FILE"; then
                echo "include \"$BIND_CONFIG_DIR/named.conf.options\";" >> "$BIND_CONFIG_FILE"
            fi
            ;;
    esac
    
    # Create directory for custom zone files if needed
    mkdir -p "$ZONES_DIR" 2>/dev/null
    
    echo -e "${GREEN}Basic BIND configuration completed.${NC}"
}

# Function to configure a forward zone
configure_forward_zone() {
    echo -e "${CYAN}Configuring a forward zone...${NC}"
    
    # Get domain name from user
    echo -e "${YELLOW}Enter the domain name you want to configure (e.g., example.com):${NC}"
    read domain_name
    
    if [ -z "$domain_name" ]; then
        echo -e "${RED}No domain name provided. Skipping forward zone configuration.${NC}"
        return
    fi
    
    # Get primary server IP address
    echo -e "${YELLOW}Enter the primary IP address for this domain:${NC}"
    read primary_ip
    
    if [ -z "$primary_ip" ]; then
        echo -e "${RED}No IP address provided. Using default 192.168.1.100${NC}"
        primary_ip="192.168.1.100"
    fi

    # Create zone file
    zone_file="$ZONES_DIR/db.$domain_name"
    cat > "$zone_file" << EOF
\$TTL 86400      ; 1 day
@       IN SOA  ns1.$domain_name. admin.$domain_name. (
                    $(date +%Y%m%d)01 ; serial
                    3600       ; refresh (1 hour)
                    1800       ; retry (30 minutes)
                    604800     ; expire (1 week)
                    86400      ; minimum (1 day)
                    )
        IN      NS      ns1.$domain_name.
        IN      NS      ns2.$domain_name.
        IN      MX      10 mail.$domain_name.
        IN      A       $primary_ip

; Name servers
ns1     IN      A       $primary_ip
ns2     IN      A       $primary_ip

; Mail servers
mail    IN      A       $primary_ip

; Other common records
www     IN      A       $primary_ip
ftp     IN      A       $primary_ip
EOF

    # Create named.conf.local if it doesn't exist
    conf_local="$BIND_CONFIG_DIR/named.conf.local"
    if [ ! -f "$conf_local" ]; then
        touch "$conf_local"
    fi
    
    # Add zone to named.conf.local
    cat >> "$conf_local" << EOF

zone "$domain_name" {
    type master;
    file "$zone_file";
    allow-query { any; };
    allow-transfer { none; };
};
EOF
    
    # Update main config to include our local zones
    case $OS in
        ubuntu|debian)
            if ! grep -q "named.conf.local" "$BIND_CONFIG_FILE"; then
                echo 'include "/etc/bind/named.conf.local";' >> "$BIND_CONFIG_FILE"
            fi
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if ! grep -q "named.conf.local" "$BIND_CONFIG_FILE"; then
                echo "include \"$BIND_CONFIG_DIR/named.conf.local\";" >> "$BIND_CONFIG_FILE"
            fi
            ;;
    esac
    
    # Set proper permissions
    case $OS in
        ubuntu|debian)
            chown -R bind:bind "$zone_file"
            ;;
        centos|rhel|fedora|rocky|almalinux)
            chown -R named:named "$zone_file"
            ;;
    esac
    
    echo -e "${GREEN}Forward zone for $domain_name has been configured.${NC}"
}

# Function to configure a reverse zone
configure_reverse_zone() {
    echo -e "${CYAN}Configuring a reverse zone...${NC}"
    
    # Get network details from user
    echo -e "${YELLOW}Enter the IP network address (e.g., 192.168.1):${NC}"
    read network

    if [ -z "$network" ]; then
        echo -e "${RED}No network provided. Skipping reverse zone configuration.${NC}"
        return
    fi
    
    # Extract network components
    IFS='.' read -r octet1 octet2 octet3 <<< "$network"
    
    if [ -z "$octet3" ]; then
        echo -e "${RED}Invalid network format. Please use format like 192.168.1${NC}"
        return
    fi
    
    # Get domain name for PTR records
    echo -e "${YELLOW}Enter the domain name for PTR records (e.g., example.com):${NC}"
    read domain_name
    
    if [ -z "$domain_name" ]; then
        echo -e "${RED}No domain name provided. Using 'example.com' as default.${NC}"
        domain_name="example.com"
    fi
    
    # Construct reverse zone name
    reverse_zone="${octet3}.${octet2}.${octet1}.in-addr.arpa"
    
    # Create reverse zone file
    zone_file="$ZONES_DIR/db.$reverse_zone"
    cat > "$zone_file" << EOF
\$TTL 86400      ; 1 day
@       IN SOA  ns1.$domain_name. admin.$domain_name. (
                    $(date +%Y%m%d)01 ; serial
                    3600       ; refresh (1 hour)
                    1800       ; retry (30 minutes)
                    604800     ; expire (1 week)
                    86400      ; minimum (1 day)
                    )
        IN      NS      ns1.$domain_name.
        IN      NS      ns2.$domain_name.

; PTR Records
100     IN      PTR     www.$domain_name.
101     IN      PTR     mail.$domain_name.
102     IN      PTR     ftp.$domain_name.
1       IN      PTR     router.$domain_name.
EOF

    # Create named.conf.local if it doesn't exist
    conf_local="$BIND_CONFIG_DIR/named.conf.local"
    if [ ! -f "$conf_local" ]; then
        touch "$conf_local"
    fi
    
    # Add reverse zone to named.conf.local
    cat >> "$conf_local" << EOF

zone "$reverse_zone" {
    type master;
    file "$zone_file";
    allow-query { any; };
    allow-transfer { none; };
};
EOF
    
    # Update main config to include our local zones if needed
    case $OS in
        ubuntu|debian)
            if ! grep -q "named.conf.local" "$BIND_CONFIG_FILE"; then
                echo 'include "/etc/bind/named.conf.local";' >> "$BIND_CONFIG_FILE"
            fi
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if ! grep -q "named.conf.local" "$BIND_CONFIG_FILE"; then
                echo "include \"$BIND_CONFIG_DIR/named.conf.local\";" >> "$BIND_CONFIG_FILE"
            fi
            ;;
    esac
    
    # Set proper permissions
    case $OS in
        ubuntu|debian)
            chown -R bind:bind "$zone_file"
            ;;
        centos|rhel|fedora|rocky|almalinux)
            chown -R named:named "$zone_file"
            ;;
    esac
    
    echo -e "${GREEN}Reverse zone for $reverse_zone has been configured.${NC}"
}

# Function to verify and restart BIND
verify_and_restart() {
    echo -e "${CYAN}Verifying BIND configuration...${NC}"
    
    case $OS in
        ubuntu|debian)
            named-checkconf
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}Configuration syntax is valid.${NC}"
                
                # Restart BIND service
                systemctl restart named
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}BIND service restarted successfully.${NC}"
                    systemctl status named --no-pager
                else
                    echo -e "${RED}Failed to restart BIND service.${NC}"
                    exit 1
                fi
            else
                echo -e "${RED}Configuration syntax check failed. Please check your configuration.${NC}"
                exit 1
            fi
            ;;
        centos|rhel|fedora|rocky|almalinux)
            named-checkconf
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}Configuration syntax is valid.${NC}"
                
                # Restart BIND service
                systemctl restart named
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}BIND service restarted successfully.${NC}"
                    systemctl status named --no-pager
                else
                    echo -e "${RED}Failed to restart BIND service.${NC}"
                    exit 1
                fi
            else
                echo -e "${RED}Configuration syntax check failed. Please check your configuration.${NC}"
                exit 1
            fi
            ;;
    esac
}

# Main function
main() {
    echo -e "${CYAN}======================================${NC}"
    echo -e "${GREEN}BIND DNS Server Installation & Configuration${NC}"
    echo -e "${CYAN}======================================${NC}"
    
    # Check if running as root
    check_root
    
    # Detect OS
    detect_os
    
    # Check if BIND is installed
    check_bind_installed
    bind_installed=$?
    
    # Install BIND if not installed
    if [ $bind_installed -eq 1 ]; then
        echo -e "${YELLOW}Would you like to install BIND? (y/n)${NC}"
        read -r install_choice
        if [[ $install_choice =~ ^[Yy]$ ]]; then
            install_bind
        else
            echo -e "${RED}BIND installation canceled. Exiting.${NC}"
            exit 0
        fi
    fi
    
    # Get BIND paths based on OS
    get_bind_paths
    
    # Configuration menu
    while true; do
        echo -e "\n${CYAN}======================================${NC}"
        echo -e "${GREEN}BIND Configuration Menu${NC}"
        echo -e "${CYAN}======================================${NC}"
        echo -e "1. Configure basic BIND settings"
        echo -e "2. Configure a forward zone"
        echo -e "3. Configure a reverse zone"
        echo -e "4. Verify configuration and restart BIND"
        echo -e "5. Exit"
        echo -e "${YELLOW}Enter your choice (1-5):${NC}"
        read -r choice
        
        case $choice in
            1)
                configure_bind_basic
                ;;
            2)
                configure_forward_zone
                ;;
            3)
                configure_reverse_zone
                ;;
            4)
                verify_and_restart
                ;;
            5)
                echo -e "${GREEN}Exiting BIND configuration script.${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid choice. Please enter a number between 1 and 5.${NC}"
                ;;
        esac
    done
}

# Execute main function
main
