#!/bin/bash

##############################################################
# NGINX Domain Manager Script
# Author: script-php - May 12, 2025
#
# This script helps manage domains on an NGINX web server:
# - Add new domains with proper directory structure
# - Configure NGINX server blocks (standalone or proxy to Apache)
# - Set up PHP-FPM configurations
# - Manage SSL certificates (optional)
# - List all configured domains
# - Remove domains
#
# IMPORTANT: Run this script as root
##############################################################

# Text colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default settings
WEB_ROOT="/var/www"
NGINX_AVAILABLE="/etc/nginx/sites-available"
NGINX_ENABLED="/etc/nginx/sites-enabled"
PHP_VERSION="8.2"  # Default PHP version
APACHE_SITES_AVAILABLE="/etc/apache2/sites-available"
APACHE_SITES_ENABLED="/etc/apache2/sites-enabled"

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}" >&2
    echo "Please run with: sudo bash $0"
    exit 1
fi

# Function to display status messages
print_status() {
    echo -e "\n${CYAN}[*] $1${NC}"
}

print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

print_error() {
    echo -e "${RED}[✗] $1${NC}" >&2
}

# Function to validate domain name
validate_domain() {
    local domain=$1
    if [[ ! $domain =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 1
    fi
    return 0
}

# Function to check if domain already exists
domain_exists() {
    local domain=$1
    if [ -f "$NGINX_AVAILABLE/$domain.conf" ] || [ -d "$WEB_ROOT/$domain" ]; then
        return 0  # Domain exists
    fi
    return 1  # Domain doesn't exist
}

# Function to detect available PHP versions
get_php_versions() {
    find /etc/php -maxdepth 1 -type d | grep -o '[0-9]\.[0-9]' | sort
}

# Function to create Apache configuration for proxy setup
create_apache_config() {
    local domain=$1
    local doc_root=$2
    local php_ver=$3
    
    # Create Apache configuration
    cat > "$APACHE_SITES_AVAILABLE/$domain.conf" << EOL
<VirtualHost 127.0.0.1:8080>
    ServerName $domain
    ServerAlias $(echo $server_aliases)
    
    DocumentRoot $doc_root/public_html
    
    <Directory $doc_root/public_html>
        Options -Indexes +FollowSymLinks +MultiViews
        AllowOverride All
        Require all granted
    </Directory>
    
    ErrorLog $doc_root/logs/apache_error.log
    CustomLog $doc_root/logs/apache_access.log combined
    
    <FilesMatch \.php$>
        SetHandler "proxy:unix:/var/run/php/php$php_ver-fpm.sock|fcgi://localhost"
    </FilesMatch>
</VirtualHost>
EOL

    # Enable the site in Apache
    a2ensite "$domain.conf"
    systemctl reload apache2
}

# Function to add a new domain
add_domain() {
    print_status "Adding new domain..."
    
    # Get domain name
    read -p "Enter domain name (e.g., example.com): " domain_name
    
    # Validate domain
    if ! validate_domain "$domain_name"; then
        print_error "Invalid domain name format!"
        return 1
    fi
    
    # Check if domain already exists
    if domain_exists "$domain_name"; then
        print_error "Domain already exists!"
        return 1
    fi
    
    # Ask for document root directory
    read -p "Enter document root directory [default: $WEB_ROOT/$domain_name]: " doc_root
    doc_root=${doc_root:-$WEB_ROOT/$domain_name}
    
    # Ask for PHP version to use
    echo "Available PHP versions:"
    available_php_versions=($(get_php_versions))
    
    if [ ${#available_php_versions[@]} -eq 0 ]; then
        print_warning "No PHP versions detected. Using system default."
        php_ver=$PHP_VERSION
    else
        PS3="Select PHP version to use: "
        select php_ver in "${available_php_versions[@]}"; do
            if [ -n "$php_ver" ]; then
                break
            else
                echo "Invalid selection. Please try again."
            fi
        done
    fi
    
    # Ask for server type
    echo -e "\nSelect server configuration:"
    echo "1) NGINX standalone (recommended)"
    echo "2) NGINX proxying to Apache"
    read -p "Enter your choice [1-2] [default: 1]: " server_type
    server_type=${server_type:-1}
    
    # Ask if SSL should be enabled
    read -p "Enable SSL? (y/n) [default: n]: " enable_ssl
    enable_ssl=${enable_ssl:-n}
    
    # Ask for additional domain names (ServerAlias)
    read -p "Enter additional domain names (space-separated, e.g., www.example.com staging.example.com): " server_aliases
    
    # Create directory structure
    print_status "Creating directory structure for $domain_name..."
    mkdir -p "$doc_root"
    mkdir -p "$doc_root/public_html"
    mkdir -p "$doc_root/logs"
    
    # Create a simple index file
    cat > "$doc_root/public_html/index.php" << EOL
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to $domain_name</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            color: #2980b9;
        }
        .info {
            background-color: #f8f9fa;
            border-left: 4px solid #2980b9;
            padding: 15px;
            margin: 20px 0;
        }
        .footer {
            margin-top: 40px;
            font-size: 0.8em;
            color: #7f8c8d;
        }
    </style>
</head>
<body>
    <h1>Welcome to $domain_name!</h1>
    <p>Your new website has been successfully set up on the server.</p>
    
    <div class="info">
        <h2>Server Information</h2>
        <p>Domain: <?php echo "$domain_name"; ?></p>
        <p>Document Root: <?php echo "$doc_root/public_html"; ?></p>
        <p>Server Software: <?php echo \$_SERVER['SERVER_SOFTWARE']; ?></p>
        <p>PHP Version: <?php echo phpversion(); ?></p>
        <p>Date & Time: <?php echo date('Y-m-d H:i:s'); ?></p>
    </div>
    
    <p>To replace this page, upload your website files to: <strong><?php echo "$doc_root/public_html"; ?></strong></p>
    
    <div class="footer">
        <p>This page was automatically generated by the NGINX Domain Manager.</p>
    </div>

    <?php phpinfo(); ?>
</body>
</html>
EOL

    # Create NGINX server block
    print_status "Creating NGINX server block for $domain_name..."
    
    if [ "$server_type" -eq 1 ]; then
        # NGINX standalone configuration
        cat > "$NGINX_AVAILABLE/$domain_name.conf" << EOL
server {
    listen 80;
    listen [::]:80;
    
    server_name $domain_name $(echo $server_aliases);
    
    root $doc_root/public_html;
    index index.php index.html index.htm;
    
    access_log $doc_root/logs/access.log;
    error_log $doc_root/logs/error.log;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php$php_ver-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    location ~ /\.ht {
        deny all;
    }
}
EOL
    else
        # NGINX proxying to Apache configuration
        print_status "Setting up NGINX to proxy to Apache..."
        
        # Check if Apache is installed
        if ! command -v apache2 &> /dev/null; then
            print_warning "Apache not found. Installing Apache..."
            apt-get update
            apt-get install -y apache2
            systemctl start apache2
        fi
        
        # Configure Apache to listen on port 8080
        if ! grep -q "Listen 8080" /etc/apache2/ports.conf; then
            echo "Listen 8080" >> /etc/apache2/ports.conf
        fi
        
        # Create Apache configuration
        create_apache_config "$domain_name" "$doc_root" "$php_ver"
        
        # Create NGINX proxy configuration
        cat > "$NGINX_AVAILABLE/$domain_name.conf" << EOL
server {
    listen 80;
    listen [::]:80;
    
    server_name $domain_name $(echo $server_aliases);
    
    access_log $doc_root/logs/access.log;
    error_log $doc_root/logs/error.log;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    location ~ /\.ht {
        deny all;
    }
}
EOL
    fi
    
    # Add SSL configuration if requested
    if [[ "$enable_ssl" == "y" || "$enable_ssl" == "Y" ]]; then
        print_status "Setting up SSL configuration..."
        
        # Check if certbot is installed
        if ! command -v certbot &> /dev/null; then
            print_warning "Certbot not found. Installing certbot..."
            apt-get update
            apt-get install -y certbot python3-certbot-nginx
        fi
        
        # Ask if user wants to obtain a Let's Encrypt certificate
        read -p "Obtain Let's Encrypt certificate? (y/n) [default: y]: " get_cert
        get_cert=${get_cert:-y}
        
        if [[ "$get_cert" == "y" || "$get_cert" == "Y" ]]; then
            print_status "Attempting to obtain Let's Encrypt certificate..."
            # Enable the site first (required for certbot)
            ln -sf "$NGINX_AVAILABLE/$domain_name.conf" "$NGINX_ENABLED/"
            systemctl reload nginx
            
            # Get certificate
            certbot --nginx -d "$domain_name" $(for alias in $server_aliases; do echo -n "-d $alias "; done)
            
            if [ $? -ne 0 ]; then
                print_warning "Failed to obtain Let's Encrypt certificate. Setting up self-signed certificate instead."
                setup_self_signed=true
            fi
        else
            setup_self_signed=true
        fi
        
        # Set up self-signed certificate if needed
        if [ "$setup_self_signed" = true ]; then
            print_status "Setting up self-signed SSL certificate..."
            mkdir -p /etc/nginx/ssl/$domain_name
            
            # Generate self-signed certificate
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout /etc/nginx/ssl/$domain_name/nginx.key \
                -out /etc/nginx/ssl/$domain_name/nginx.crt \
                -subj "/CN=$domain_name"
            
            # Update NGINX configuration with SSL
            if [ "$server_type" -eq 1 ]; then
                # NGINX standalone SSL config
                cat > "$NGINX_AVAILABLE/$domain_name.conf" << EOL
server {
    listen 80;
    listen [::]:80;
    server_name $domain_name $(echo $server_aliases);
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    
    server_name $domain_name $(echo $server_aliases);
    
    ssl_certificate /etc/nginx/ssl/$domain_name/nginx.crt;
    ssl_certificate_key /etc/nginx/ssl/$domain_name/nginx.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    
    root $doc_root/public_html;
    index index.php index.html index.htm;
    
    access_log $doc_root/logs/access.log;
    error_log $doc_root/logs/error.log;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php$php_ver-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    location ~ /\.ht {
        deny all;
    }
}
EOL
            else
                # NGINX proxy to Apache SSL config
                cat > "$NGINX_AVAILABLE/$domain_name.conf" << EOL
server {
    listen 80;
    listen [::]:80;
    server_name $domain_name $(echo $server_aliases);
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    
    server_name $domain_name $(echo $server_aliases);
    
    ssl_certificate /etc/nginx/ssl/$domain_name/nginx.crt;
    ssl_certificate_key /etc/nginx/ssl/$domain_name/nginx.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    
    access_log $doc_root/logs/access.log;
    error_log $doc_root/logs/error.log;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    location ~ /\.ht {
        deny all;
    }
}
EOL
            fi
        fi
    fi
    
    # Enable the site if not already done by certbot
    if [ ! -L "$NGINX_ENABLED/$domain_name.conf" ]; then
        ln -sf "$NGINX_AVAILABLE/$domain_name.conf" "$NGINX_ENABLED/"
    fi
    
    # Set proper permissions
    chown -R www-data:www-data "$doc_root"
    find "$doc_root" -type d -exec chmod 755 {} \;
    find "$doc_root" -type f -exec chmod 644 {} \;
    
    # Reload NGINX to apply changes
    systemctl reload nginx
    
    # Output success message
    print_success "Domain $domain_name has been successfully added!"
    echo -e "Website URL: http://$domain_name"
    if [[ "$enable_ssl" == "y" || "$enable_ssl" == "Y" ]]; then
        echo -e "Secure URL: https://$domain_name"
    fi
    echo -e "Web Root: $doc_root/public_html"
    echo -e "Config File: $NGINX_AVAILABLE/$domain_name.conf"
    if [ "$server_type" -eq 2 ]; then
        echo -e "Apache Config File: $APACHE_SITES_AVAILABLE/$domain_name.conf"
    fi
}

# Function to list all domains
list_domains() {
    print_status "Listing all configured domains..."
    
    domains=($(find "$NGINX_AVAILABLE" -name "*.conf" -exec basename {} \; | sed 's/\.conf//'))
    
    if [ ${#domains[@]} -eq 0 ]; then
        echo "No domains are currently configured."
        return
    fi
    
    printf "%-30s %-20s %-10s %-15s %-30s\n" "DOMAIN" "STATUS" "SSL" "SERVER TYPE" "DOCUMENT ROOT"
    echo "----------------------------------------------------------------------------------------------------"
    
    for domain in "${domains[@]}"; do
        # Get status (enabled/disabled)
        if [ -L "$NGINX_ENABLED/$domain.conf" ]; then
            status="${GREEN}enabled${NC}"
        else
            status="${RED}disabled${NC}"
        fi
        
        # Check if SSL is configured
        if grep -q "ssl" "$NGINX_AVAILABLE/$domain.conf"; then
            ssl="${GREEN}Yes${NC}"
        else
            ssl="${RED}No${NC}"
        fi
        
        # Check server type
        if grep -q "proxy_pass" "$NGINX_AVAILABLE/$domain.conf"; then
            server_type="NGINX+Apache"
        else
            server_type="NGINX only"
        fi
        
        # Get document root
        if [ "$server_type" == "NGINX only" ]; then
            doc_root=$(grep -m 1 "root" "$NGINX_AVAILABLE/$domain.conf" | awk '{print $2}' | sed 's/;$//')
        else
            doc_root=$(grep -m 1 "DocumentRoot" "$APACHE_SITES_AVAILABLE/$domain.conf" | awk '{print $2}' | sed 's/;$//' | sed 's/\/public_html//')
        fi
        
        printf "%-30s %-20b %-10b %-15s %-30s\n" "$domain" "$status" "$ssl" "$server_type" "$doc_root"
    done
}

# Function to remove a domain
remove_domain() {
    print_status "Removing domain..."
    
    # List available domains
    domains=($(find "$NGINX_AVAILABLE" -name "*.conf" -exec basename {} \; | sed 's/\.conf//'))
    
    if [ ${#domains[@]} -eq 0 ]; then
        print_error "No domains are currently configured."
        return 1
    fi
    
    echo "Available domains:"
    PS3="Select domain to remove (or 0 to cancel): "
    select domain in "Cancel" "${domains[@]}"; do
        if [ "$REPLY" -eq 1 ]; then
            echo "Operation cancelled."
            return
        elif [ -n "$domain" ]; then
            break
        else
            echo "Invalid selection. Please try again."
        fi
    done
    
    # Confirm removal
    read -p "Are you sure you want to remove $domain? This will delete all associated files. (y/n) [default: n]: " confirm
    confirm=${confirm:-n}
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "Operation cancelled."
        return
    fi
    
    # Get document root for this domain
    if grep -q "proxy_pass" "$NGINX_AVAILABLE/$domain.conf"; then
        # NGINX+Apache setup
        doc_root=$(grep -m 1 "DocumentRoot" "$APACHE_SITES_AVAILABLE/$domain.conf" | awk '{print $2}' | sed 's/;$//' | sed 's/\/public_html//')
    else
        # NGINX only setup
        doc_root=$(grep -m 1 "root" "$NGINX_AVAILABLE/$domain.conf" | awk '{print $2}' | sed 's/;$//' | sed 's/\/public_html//')
    fi
    
    # Remove NGINX configuration
    print_status "Removing NGINX configuration for $domain..."
    rm -f "$NGINX_ENABLED/$domain.conf"
    rm -f "$NGINX_AVAILABLE/$domain.conf"
    
    # Remove Apache configuration if it exists
    if [ -f "$APACHE_SITES_AVAILABLE/$domain.conf" ]; then
        print_status "Removing Apache configuration for $domain..."
        a2dissite "$domain.conf" > /dev/null 2>&1
        rm -f "$APACHE_SITES_ENABLED/$domain.conf"
        rm -f "$APACHE_SITES_AVAILABLE/$domain.conf"
        systemctl reload apache2
    fi
    
    # Ask if files should be removed
    read -p "Remove website files in $doc_root? (y/n) [default: n]: " remove_files
    remove_files=${remove_files:-n}
    
    if [[ "$remove_files" == "y" || "$remove_files" == "Y" ]]; then
        print_status "Removing website files for $domain..."
        rm -rf "$doc_root"
    else
        print_warning "Website files kept in $doc_root"
    fi
    
    # Remove SSL certificates if they exist
    if [ -d "/etc/nginx/ssl/$domain" ]; then
        print_status "Removing SSL certificates for $domain..."
        rm -rf "/etc/nginx/ssl/$domain"
    fi
    
    # Check if Let's Encrypt certificates exist
    if [ -d "/etc/letsencrypt/live/$domain" ]; then
        read -p "Remove Let's Encrypt certificates for $domain? (y/n) [default: n]: " remove_le
        remove_le=${remove_le:-n}
        
        if [[ "$remove_le" == "y" || "$remove_le" == "Y" ]]; then
            print_status "Removing Let's Encrypt certificates for $domain..."
            certbot delete --cert-name "$domain"
        fi
    fi
    
    # Reload NGINX to apply changes
    systemctl reload nginx
    
    print_success "Domain $domain has been successfully removed!"
}

# Function to enable a domain
enable_domain() {
    print_status "Enabling domain..."
    
    # Get list of disabled domains
    disabled_domains=()
    for conf in "$NGINX_AVAILABLE"/*.conf; do
        domain=$(basename "$conf" .conf)
        if [ ! -L "$NGINX_ENABLED/$domain.conf" ]; then
            disabled_domains+=("$domain")
        fi
    done
    
    if [ ${#disabled_domains[@]} -eq 0 ]; then
        print_error "No disabled domains found."
        return 1
    fi
    
    echo "Disabled domains:"
    PS3="Select domain to enable (or 0 to cancel): "
    select domain in "Cancel" "${disabled_domains[@]}"; do
        if [ "$REPLY" -eq 1 ]; then
            echo "Operation cancelled."
            return
        elif [ -n "$domain" ]; then
            break
        else
            echo "Invalid selection. Please try again."
        fi
    done
    
    # Enable the domain
    ln -sf "$NGINX_AVAILABLE/$domain.conf" "$NGINX_ENABLED/"
    
    # If this is an NGINX+Apache setup, enable Apache config too
    if [ -f "$APACHE_SITES_AVAILABLE/$domain.conf" ] && [ ! -L "$APACHE_SITES_ENABLED/$domain.conf" ]; then
        a2ensite "$domain.conf"
        systemctl reload apache2
    fi
    
    # Reload NGINX to apply changes
    systemctl reload nginx
    
    print_success "Domain $domain has been successfully enabled!"
}

# Function to disable a domain
disable_domain() {
    print_status "Disabling domain..."
    
    # Get list of enabled domains
    enabled_domains=()
    for conf in "$NGINX_ENABLED"/*.conf; do
        domain=$(basename "$conf" .conf)
        enabled_domains+=("$domain")
    done
    
    if [ ${#enabled_domains[@]} -eq 0 ]; then
        print_error "No enabled domains found."
        return 1
    fi
    
    echo "Enabled domains:"
    PS3="Select domain to disable (or 0 to cancel): "
    select domain in "Cancel" "${enabled_domains[@]}"; do
        if [ "$REPLY" -eq 1 ]; then
            echo "Operation cancelled."
            return
        elif [ -n "$domain" ]; then
            break
        else
            echo "Invalid selection. Please try again."
        fi
    done
    
    # Disable the domain in NGINX
    rm -f "$NGINX_ENABLED/$domain.conf"
    
    # If this is an NGINX+Apache setup, disable Apache config too
    if [ -L "$APACHE_SITES_ENABLED/$domain.conf" ]; then
        a2dissite "$domain.conf"
        systemctl reload apache2
    fi
    
    # Reload NGINX to apply changes
    systemctl reload nginx
    
    print_success "Domain $domain has been successfully disabled!"
}

# Function to show domain details
show_domain_details() {
    print_status "Showing domain details..."
    
    domains=($(find "$NGINX_AVAILABLE" -name "*.conf" -exec basename {} \; | sed 's/\.conf//'))
    
    if [ ${#domains[@]} -eq 0 ]; then
        print_error "No domains are currently configured."
        return 1
    fi
    
    echo "Available domains:"
    PS3="Select domain to view details (or 0 to cancel): "
    select domain in "Cancel" "${domains[@]}"; do
        if [ "$REPLY" -eq 1 ]; then
            echo "Operation cancelled."
            return
        elif [ -n "$domain" ]; then
            break
        else
            echo "Invalid selection. Please try again."
        fi
    done
    
    # Get domain details
    conf_file="$NGINX_AVAILABLE/$domain.conf"
    
    # Check if domain is enabled
    if [ -L "$NGINX_ENABLED/$domain.conf" ]; then
        status="${GREEN}Enabled${NC}"
    else
        status="${RED}Disabled${NC}"
    fi
    
    # Check server type
    if grep -q "proxy_pass" "$conf_file"; then
        server_type="NGINX proxying to Apache"
        apache_conf_file="$APACHE_SITES_AVAILABLE/$domain.conf"
    else
        server_type="NGINX standalone"
    fi
    
    # Check if SSL is configured
    if grep -q "ssl" "$conf_file"; then
        ssl="${GREEN}Enabled${NC}"
        
        # Check certificate type
        if grep -q "letsencrypt" "$conf_file" || grep -q "certbot" "$conf_file"; then
            cert_type="Let's Encrypt"
        elif grep -q "/etc/nginx/ssl/$domain" "$conf_file"; then
            cert_type="Self-signed"
        else
            cert_type="Unknown"
        fi
    else
        ssl="${RED}Disabled${NC}"
        cert_type="N/A"
    fi
    
    # Get document root
    if [ "$server_type" == "NGINX standalone" ]; then
        doc_root=$(grep -m 1 "root" "$conf_file" | awk '{print $2}' | sed 's/;$//')
    else
        doc_root=$(grep -m 1 "DocumentRoot" "$apache_conf_file" | awk '{print $2}' | sed 's/;$//')
    fi
    
    # Get server names
    server_names=$(grep -m 1 "server_name" "$conf_file" | cut -d';' -f1 | sed 's/server_name//' | tr -d ';')
    
    # Get PHP version
    if [ "$server_type" == "NGINX standalone" ]; then
        php_version=$(grep -m 1 "fastcgi_pass" "$conf_file" | grep -o "php[0-9]\.[0-9]" | sed 's/php//')
    else
        php_version=$(grep -m 1 "SetHandler" "$apache_conf_file" | grep -o "php[0-9]\.[0-9]" | sed 's/php//')
    fi
    
    # Get log files
    access_log=$(grep -m 1 "access_log" "$conf_file" | awk '{print $2}' | sed 's/;$//')
    error_log=$(grep -m 1 "error_log" "$conf_file" | awk '{print $2}' | sed 's/;$//')
    
    # Print details
    echo -e "\n${CYAN}Domain Details for $domain${NC}"
    echo -e "Status: $status"
    echo -e "Server Type: $server_type"
    echo -e "Configuration File: $conf_file"
    if [ "$server_type" == "NGINX proxying to Apache" ]; then
        echo -e "Apache Config File: $apache_conf_file"
    fi
    echo -e "Document Root: $doc_root"
    echo -e "Server Names: $server_names"
    echo -e "PHP Version: $php_version"
    echo -e "SSL: $ssl"
    echo -e "Certificate Type: $cert_type"
    echo -e "Access Log: $access_log"
    echo -e "Error Log: $error_log"
    
    # Show SSL certificate details if SSL is enabled
    if [[ "$ssl" == *"Enabled"* ]]; then
        echo -e "\n${CYAN}SSL Certificate Details:${NC}"
        
        if [ "$cert_type" == "Let's Encrypt" ]; then
            # Try to find Let's Encrypt certificate
            if [ -d "/etc/letsencrypt/live/$domain" ]; then
                cert_file=$(find /etc/letsencrypt/live/$domain -name "cert.pem" | head -n 1)
                if [ -n "$cert_file" ]; then
                    openssl x509 -in "$cert_file" -noout -text | grep -E "Issuer:|Subject:|Not Before:|Not After :|DNS:"
                else
                    echo "Certificate file not found."
                fi
            else
                echo "Let's Encrypt certificate directory not found."
            fi
        elif [ "$cert_type" == "Self-signed" ]; then
            if [ -f "/etc/nginx/ssl/$domain/nginx.crt" ]; then
                openssl x509 -in "/etc/nginx/ssl/$domain/nginx.crt" -noout -text | grep -E "Issuer:|Subject:|Not Before:|Not After :"
            else
                echo "Self-signed certificate file not found."
            fi
        fi
    fi
}

# Function to edit domain configuration
edit_domain_config() {
    print_status "Editing domain configuration..."
    
    domains=($(find "$NGINX_AVAILABLE" -name "*.conf" -exec basename {} \; | sed 's/\.conf//'))
    
    if [ ${#domains[@]} -eq 0 ]; then
        print_error "No domains are currently configured."
        return 1
    fi
    
    echo "Available domains:"
    PS3="Select domain configuration to edit (or 0 to cancel): "
    select domain in "Cancel" "${domains[@]}"; do
        if [ "$REPLY" -eq 1 ]; then
            echo "Operation cancelled."
            return
        elif [ -n "$domain" ]; then
            break
        else
            echo "Invalid selection. Please try again."
        fi
    done
    
    # Check if editor is available
    editors=("nano" "vim" "vi")
    editor=""
    
    for e in "${editors[@]}"; do
        if command -v "$e" &> /dev/null; then
            editor="$e"
            break
        fi
    done
    
    if [ -z "$editor" ]; then
        print_error "No text editor found. Please install nano, vim, or vi."
        return 1
    fi
    
    # Edit configuration
    "$editor" "$NGINX_AVAILABLE/$domain.conf"
    
    # Check if this is an NGINX+Apache setup and edit Apache config if needed
    if grep -q "proxy_pass" "$NGINX_AVAILABLE/$domain.conf" && [ -f "$APACHE_SITES_AVAILABLE/$domain.conf" ]; then
        echo -e "\n${YELLOW}This domain uses NGINX proxying to Apache. Would you like to edit the Apache configuration as well?${NC}"
        read -p "Edit Apache configuration? (y/n) [default: n]: " edit_apache
        edit_apache=${edit_apache:-n}
        
        if [[ "$edit_apache" == "y" || "$edit_apache" == "Y" ]]; then
            "$editor" "$APACHE_SITES_AVAILABLE/$domain.conf"
        fi
    fi
    
    # Check NGINX configuration
    print_status "Checking NGINX configuration syntax..."
    nginx -t
    
    if [ $? -eq 0 ]; then
        # Reload NGINX to apply changes
        systemctl reload nginx
        print_success "Configuration for $domain has been updated and NGINX reloaded."
    else
        print_error "NGINX configuration test failed. Please fix the errors and reload manually with 'systemctl reload nginx'."
    fi
    
    # If Apache config was edited, reload Apache
    if [[ "$edit_apache" == "y" || "$edit_apache" == "Y" ]]; then
        print_status "Reloading Apache..."
        systemctl reload apache2
    fi
}

# Main menu function
show_menu() {
    clear
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}               DOMAIN MANAGER               ${NC}"
    echo -e "${CYAN}============================================${NC}"
    echo -e "1. Add new domain"
    echo -e "2. List all domains"
    echo -e "3. Show domain details"
    echo -e "4. Edit domain configuration"
    echo -e "5. Enable domain"
    echo -e "6. Disable domain"
    echo -e "7. Remove domain"
    echo -e "8. Exit"
    echo -e "${CYAN}============================================${NC}"
    echo ""
}

# Main script
while true; do
    show_menu
    read -p "Please enter your choice [1-8]: " choice
    
    case $choice in
        1) add_domain ;;
        2) list_domains ;;
        3) show_domain_details ;;
        4) edit_domain_config ;;
        5) enable_domain ;;
        6) disable_domain ;;
        7) remove_domain ;;
        8) echo "Exiting..."; exit 0 ;;
        *) echo "Invalid option, please try again." ;;
    esac
    
    echo ""
    read -p "Press Enter to continue..."
done