#!/bin/bash

##############################################################
# Ubuntu Multi-PHP LEMP Stack Installer
# Author: script-php - May 12, 2025
#
# This script installs:
# - PHP versions 5.6 through 8.2
# - NGINX web server
# - MariaDB database server
# - phpMyAdmin
# - Fail2Ban
# - UFW (with rules for ports 80, 443, and 22)
# - Optional root SSH access configuration
#
# IMPORTANT: Run this script as root on a fresh Ubuntu system
##############################################################


# Text colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color


# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}" >&2
    echo "Please run with: sudo bash $0"
    exit 1
fi


# Prompt for MariaDB root password
read -sp "Enter the desired MariaDB root password: " MYSQL_ROOT_PASSWORD
echo
read -sp "Confirm MariaDB root password: " MYSQL_ROOT_PASSWORD_CONFIRM
echo

# Check if passwords match
if [ "$MYSQL_ROOT_PASSWORD" != "$MYSQL_ROOT_PASSWORD_CONFIRM" ]; then
    echo "Passwords do not match. Exiting."
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


# Function to log messages (alias for print_status for compatibility)
log() {
    print_status "$1"
}


# Function to check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}


# Log file setup
LOG_FILE="/var/log/lemp_installer.log"
exec > >(tee -a "$LOG_FILE") 2>&1
print_status "Starting installation at $(date). Logging to $LOG_FILE"

# Function to setup root SSH access
setup_root_ssh() {
    log "Setting up root SSH access..."
    
    # Configure SSH
    sed -i -e 's/^\#\?PermitRootLogin\s[a-zA-Z\-]*$/PermitRootLogin yes/m' \
           -e 's/^\#\?PasswordAuthentication\s[a-zA-Z\-]*$/PasswordAuthentication yes/m' \
           -e 's/^\#\?PermitEmptyPasswords\s[a-zA-Z\-]*$/PermitEmptyPasswords no/' \
           -e 's/^\#\?LoginGraceTime/LoginGraceTime/m' \
           -e 's/^\#\?StrictModes/StrictModes/m' \
           -e 's/^\#\?MaxAuthTries/MaxAuthTries/m' \
           -e 's/^\#\?MaxSessions/MaxSessions/m' /etc/ssh/sshd_config
    
    # Prompt for root password
    clear
    echo "Please enter your root password in the next screen"
    passwd
    
    # Restart SSH service
    systemctl restart ssh
    systemctl restart sshd
    
    log "Root SSH access configured."
}


# Update package lists
print_status "Updating package lists..."
apt-get update || { print_error "Failed to update package lists"; exit 1; }


# Install required packages
print_status "Installing required packages..."
apt-get install -y software-properties-common apt-transport-https curl gnupg2 ca-certificates lsb-release || { 
    print_error "Failed to install required packages"; 
    exit 1; 
}


# Add repositories
print_status "Adding required repositories..."

# Add Ondřej Surý's PPA for PHP versions
if ! grep -q "ondrej/php" /etc/apt/sources.list.d/* 2>/dev/null; then
    print_status "Adding PHP repository..."
    add-apt-repository -y ppa:ondrej/php || { 
        print_error "Failed to add PHP repository"; 
        exit 1; 
    }
    print_status "Adding NGINX repository..."
    add-apt-repository -y ppa:ondrej/nginx-mainline || { 
        print_error "Failed to add NGINX repository"; 
        exit 1; 
    }
else
    print_warning "PHP repository already exists, skipping addition"
fi


# Update package lists again after adding repositories
print_status "Updating package lists with new repositories..."
apt-get update || { print_error "Failed to update package lists after adding repositories"; exit 1; }




###############################
# NGINX Installation
###############################
print_status "Checking for existing NGINX installation..."
if command_exists nginx; then
    print_warning "Removing existing NGINX installation..."
    apt-get remove --purge -y nginx nginx-common nginx-full
    apt-get autoremove -y
    rm -rf /etc/nginx /var/log/nginx
fi

print_status "Installing NGINX..."
apt-get install -y nginx || { print_error "Failed to install NGINX"; exit 1; }
systemctl enable nginx
systemctl start nginx
print_success "NGINX installed successfully"




###############################
# PHP Installation
###############################
# php_versions=("5.6" "7.0" "7.1" "7.2" "7.3" "7.4" "8.0" "8.1" "8.2")
php_versions=("7.4" "8.0" "8.1" "8.2")

# Check and remove existing PHP versions
for version in "${php_versions[@]}"; do
    if dpkg -l | grep -q "php$version"; then
        print_warning "Removing PHP $version..."
        apt-get remove --purge -y php$version-* 
        apt-get autoremove -y
    fi
done

# Install PHP versions
for version in "${php_versions[@]}"; do
    print_status "Installing PHP $version..."
    apt-get install -y php$version-fpm php$version-common php$version-mysql \
    php$version-xml php$version-xmlrpc php$version-curl php$version-gd \
    php$version-imagick php$version-cli php$version-dev php$version-imap \
    php$version-mbstring php$version-opcache php$version-soap php$version-zip php$version-intl || { 
        print_warning "Some PHP $version packages failed to install. Continuing..."; 
    }
    
    # Configure PHP
    if [ -f "/etc/php/$version/fpm/php.ini" ]; then
        print_status "Configuring PHP $version..."
        sed -i "s/^memory_limit.*/memory_limit = 256M/" /etc/php/$version/fpm/php.ini
        sed -i "s/^upload_max_filesize.*/upload_max_filesize = 64M/" /etc/php/$version/fpm/php.ini
        sed -i "s/^post_max_size.*/post_max_size = 64M/" /etc/php/$version/fpm/php.ini
        sed -i "s/^max_execution_time.*/max_execution_time = 300/" /etc/php/$version/fpm/php.ini
        
        # Restart PHP-FPM
        systemctl restart php$version-fpm
        print_success "PHP $version installed and configured"
    else
        print_warning "PHP $version configuration file not found"
    fi
done

# Create PHP version switcher script
print_status "Creating PHP version switcher script..."
cat > /usr/local/bin/phpswitch << 'EOL'
#!/bin/bash
if [ -z "$1" ]; then
    echo "Usage: phpswitch <version>"
    echo "Available versions:"
    find /etc/php -maxdepth 1 -type d | grep -o '[0-9]\.[0-9]' | sort
    exit 1
fi

VERSION=$1

if [ ! -d "/etc/php/$VERSION" ]; then
    echo "PHP version $VERSION is not installed"
    echo "Available versions:"
    find /etc/php -maxdepth 1 -type d | grep -o '[0-9]\.[0-9]' | sort
    exit 1
fi

# Update CLI symlink
update-alternatives --set php /usr/bin/php$VERSION

# Update NGINX configuration
NGINX_CONF="/etc/nginx/conf.d/php-fpm.conf"
echo "upstream php-fpm {
    server unix:/var/run/php/php$VERSION-fpm.sock;
}" > $NGINX_CONF

# Reload NGINX
systemctl reload nginx

echo "Switched to PHP $VERSION"
echo "FPM socket: /var/run/php/php$VERSION-fpm.sock"
php -v
EOL

chmod +x /usr/local/bin/phpswitch
print_success "PHP version switcher created at /usr/local/bin/phpswitch"



# Default to PHP 8.2
/usr/local/bin/phpswitch 8.2 || print_warning "Could not set PHP 8.2 as default"



# Install MariaDB
print_status "Installing MariaDB..."
apt-get update
apt-get install -y mariadb-server mariadb-client



# Secure MariaDB installation and set root password
print_status "Securing MariaDB installation..."



# Create a temp file with MySQL commands
cat > /tmp/mysql_secure_installation.sql << EOF
-- Change root password
ALTER USER 'root'@'localhost' IDENTIFIED BY '$MYSQL_ROOT_PASSWORD';
-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';
-- Disallow remote root login
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
-- Remove test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
-- Reload privilege tables
FLUSH PRIVILEGES;
EOF



# Run the SQL commands as root (no password needed for fresh install)
mysql < /tmp/mysql_secure_installation.sql



# Remove the temp file
rm /tmp/mysql_secure_installation.sql

print_status "MariaDB root password set successfully!"

echo "MariaDB root password: $MYSQL_ROOT_PASSWORD" > /root/.mariadb_credentials
chmod 600 /root/.mariadb_credentials
print_success "MariaDB installed and secured"




# Install phpMyAdmin without Apache
print_status "Installing phpMyAdmin without Apache..."

# Create a dedicated database user for phpMyAdmin (optional but more secure)
print_status "Creating dedicated phpMyAdmin user..."

# Generate a random password for the phpMyAdmin user
# PHPMYADMIN_PASSWORD=$(openssl rand -base64 12)

# Create user and grant privileges
mysql -u root -p"$MYSQL_ROOT_PASSWORD" << EOF
CREATE USER 'phpmyadmin'@'localhost' IDENTIFIED BY '$MYSQL_ROOT_PASSWORD';
GRANT ALL PRIVILEGES ON *.* TO 'phpmyadmin'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF



# First, mark apache2 packages as not to be installed
# apt-mark hold apache2 apache2-bin apache2-data apache2-utils

# Set answers for debconf to avoid interactive prompts
export DEBIAN_FRONTEND=noninteractive
echo "phpmyadmin phpmyadmin/dbconfig-install boolean true" | debconf-set-selections
echo "phpmyadmin phpmyadmin/app-password-confirm password $MYSQL_ROOT_PASSWORD" | debconf-set-selections
echo "phpmyadmin phpmyadmin/mysql/admin-pass password $MYSQL_ROOT_PASSWORD" | debconf-set-selections
echo "phpmyadmin phpmyadmin/mysql/app-pass password $MYSQL_ROOT_PASSWORD" | debconf-set-selections
echo "phpmyadmin phpmyadmin/reconfigure-webserver multiselect none" | debconf-set-selections

# Install phpMyAdmin without recommended packages (which includes Apache)
apt-get install -y --no-install-recommends phpmyadmin

# In case Apache was installed (despite our efforts), disable and stop it
if dpkg -l | grep -q apache2; then
    print_warning "Apache was installed as a dependency. Disabling it..."
    systemctl stop apache2 2>/dev/null || true
    systemctl disable apache2 2>/dev/null || true
    
    # Mask the apache2 service to prevent it from starting on boot
    systemctl mask apache2 2>/dev/null || true
    
    print_status "Apache has been disabled and masked to prevent it from starting"
fi

# Configure Nginx for phpMyAdmin manually
print_status "Configuring Nginx for phpMyAdmin..."
    
cat > /etc/nginx/conf.d/phpmyadmin.conf << EOF
server {

    # phpMyAdmin configuration
    location /phpmyadmin {
        alias /usr/share/phpmyadmin/;
        index index.php index.html index.htm;
        
        # Block access to sensitive directories
        location ~ ^/phpmyadmin/(libraries|setup|templates|locale) {
            deny all;
            return 404;
        }
        
        # Block access to sensitive files
        location ~ ^/phpmyadmin/(.+\.(json|lock|md))$ {
            deny all;
            return 404;
        }
        
        # Handle PHP files
        location ~ ^/phpmyadmin/(.+\.php)$ {
            alias /usr/share/phpmyadmin/$1;
			fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
            include fastcgi_params;
            fastcgi_index index.php;
            fastcgi_param SCRIPT_FILENAME $request_filename;
            #fastcgi_param HTTP_EARLY_DATA $rfc_early_data if_not_empty;
        }
        
        # Handle static files
        location ~ ^/phpmyadmin/(.+\.(jpg|jpeg|gif|css|png|webp|js|ico|html|xml|txt))$ {
            alias /usr/share/phpmyadmin/$1;
        }
    }
}
EOF


# Determine the PHP-FPM socket location and update the config
# PHP_FPM_SOCK=$(find /var/run/php/ -name "*.sock" | head -n 1)

# if [ -n "$PHP_FPM_SOCK" ]; then
#     sed -i "s|unix:/var/run/php/php-fpm.sock|unix:$PHP_FPM_SOCK|g" /etc/nginx/conf.d/phpmyadmin.conf
# else
#     print_warning "PHP-FPM socket not found. You may need to manually update the socket path in /etc/nginx/conf.d/phpmyadmin.conf"
# fi

# Test Nginx config and reload
nginx -t && systemctl reload nginx








###############################
# Fail2Ban Installation
###############################
print_status "Checking for existing Fail2Ban installation..."
if command_exists fail2ban-server; then
    print_warning "Removing existing Fail2Ban installation..."
    apt-get remove --purge -y fail2ban
    apt-get autoremove -y
    rm -rf /etc/fail2ban
fi  

print_status "Installing Fail2Ban..."
apt-get install -y fail2ban || { 
    print_error "Failed to install Fail2Ban"; 
    exit 1; 
}

# Configure Fail2Ban
print_status "Configuring Fail2Ban..."
cat > /etc/fail2ban/jail.local << 'EOL'
[DEFAULT]
# Ban hosts for one hour
bantime = 3600
# Find matches within 10 minutes
findtime = 600
# Ban after 5 retries
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-botsearch]
enabled = true
filter = nginx-botsearch
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 2
findtime = 300
bantime = 7200

[nginx-req-limit]
enabled = true
filter = nginx-req-limit
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 10
findtime = 60
bantime = 7200
EOL

# Restart Fail2Ban
systemctl enable fail2ban
systemctl restart fail2ban
print_success "Fail2Ban installed and configured"





###############################
# UFW (Firewall) Configuration
###############################
print_status "Checking for existing UFW installation..."
if command_exists ufw; then
    print_warning "Resetting existing UFW rules..."
    ufw --force reset
else
    print_status "Installing UFW..."
    apt-get install -y ufw || { 
        print_error "Failed to install UFW"; 
        exit 1; 
    }
fi

# Reset UFW to default settings
print_status "Resetting UFW to default settings..."
ufw --force reset

# Set default policies
print_status "Setting default policies..."

ufw default deny incoming
ufw default allow outgoing

# Allow specific ports
print_status "Allowing required ports..."
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS

# Enable UFW
print_status "Enabling UFW..."
echo "y" | ufw enable

# Display status
print_success "UFW configured with rules for ports 22, 80, and 443. Current status:"
ufw status verbose

# Restart NGINX to apply all configurations
print_status "Restarting NGINX to apply all configurations..."
systemctl restart nginx

# Create a basic NGINX server block
print_status "Creating default NGINX server block..."
cat > /etc/nginx/sites-available/default << 'EOL'
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/html;
    index index.php index.html index.htm;

    server_name _;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    # Pass PHP scripts to FastCGI server
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        # With PHP-FPM (or other unix sockets):
        # Use the currently active PHP version's socket
        fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
    }

    # Deny access to .htaccess files
    location ~ /\.ht {
        deny all;
    }
}
EOL

# Create info.php files for testing
print_status "Creating PHP info pages for testing..."
mkdir -p /var/www/html/php

for version in "${php_versions[@]}"; do
    # Create an info.php file for each PHP version
    cat > "/var/www/html/php/info$version.php" << EOL
<?php
    // Show PHP info for version $version
    phpinfo();
?>
EOL
done

# Create a main info.php file
cat > "/var/www/html/info.php" << 'EOL'
<?php
    // Show all PHP info
    phpinfo();
?>
EOL

# Set proper permissions
chown -R www-data:www-data /var/www/html
find /var/www/html -type f -exec chmod 644 {} \;
find /var/www/html -type d -exec chmod 755 {} \;

# Create a version checking script
cat > "/var/www/html/versions.php" << 'EOL'
<!DOCTYPE html>
<html>
<head>
    <title>Server Configuration</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        .container { max-width: 800px; margin: 0 auto; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .status { padding: 5px; border-radius: 3px; }
        .active { background-color: #d4edda; color: #155724; }
        .inactive { background-color: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Server Configuration</h1>
        
        <h2>System Information</h2>
        <table>
            <tr>
                <th>Component</th>
                <th>Version/Status</th>
            </tr>
            <tr>
                <td>Operating System</td>
                <td><?php echo php_uname('s') . ' ' . php_uname('r'); ?></td>
            </tr>
            <tr>
                <td>Server Software</td>
                <td><?php echo $_SERVER['SERVER_SOFTWARE']; ?></td>
            </tr>
            <tr>
                <td>Current PHP Version</td>
                <td><?php echo PHP_VERSION; ?></td>
            </tr>
            <tr>
                <td>Database</td>
                <td><?php 
                    if (function_exists('mysqli_connect')) {
                        try {
                            $mysqli = @new mysqli('localhost', 'root');
                            if (!$mysqli->connect_error) {
                                $result = $mysqli->query("SELECT VERSION() as version");
                                $row = $result->fetch_assoc();
                                echo $row['version'];
                                $mysqli->close();
                            } else {
                                echo "Database connection failed";
                            }
                        } catch (Exception $e) {
                            echo "Database connection failed";
                        }
                    } else {
                        echo "MySQLi extension not available";
                    }
                ?></td>
            </tr>
        </table>
        
        <h2>Installed PHP Versions</h2>
        <table>
            <tr>
                <th>PHP Version</th>
                <th>Status</th>
                <th>Info Page</th>
            </tr>
            <?php
            $php_versions = ['5.6', '7.0', '7.1', '7.2', '7.3', '7.4', '8.0', '8.1', '8.2'];
            
            foreach ($php_versions as $version) {
                $socket_file = "/var/run/php/php{$version}-fpm.sock";
                $status = file_exists($socket_file) ? "Running" : "Not installed or not running";
                $status_class = file_exists($socket_file) ? "active" : "inactive";
                
                echo "<tr>";
                echo "<td>PHP $version</td>";
                echo "<td><span class='status $status_class'>$status</span></td>";
                echo "<td><a href='/php/info{$version}.php'>View PHP $version Info</a></td>";
                echo "</tr>";
            }
            ?>
        </table>
        
        <h2>Server Security</h2>
        <table>
            <tr>
                <th>Component</th>
                <th>Status</th>
            </tr>
            <tr>
                <td>Fail2Ban</td>
                <td><?php 
                    exec('systemctl is-active fail2ban', $output, $return_var);
                    $status = ($return_var === 0) ? "Active" : "Inactive";
                    $status_class = ($return_var === 0) ? "active" : "inactive";
                    echo "<span class='status $status_class'>$status</span>";
                ?></td>
            </tr>
            <tr>
                <td>UFW Firewall</td>
                <td><?php
                    exec('ufw status | grep "Status: active"', $output, $return_var);
                    $status = ($return_var === 0) ? "Active" : "Inactive";
                    $status_class = ($return_var === 0) ? "active" : "inactive";
                    echo "<span class='status $status_class'>$status</span>";
                ?></td>
            </tr>
            <tr>
                <td>Root SSH Access</td>
                <td><?php
                    exec('grep "^PermitRootLogin yes" /etc/ssh/sshd_config', $output, $return_var);
                    $status = ($return_var === 0) ? "Enabled" : "Disabled";
                    $status_class = ($return_var === 0) ? "active" : "inactive";
                    echo "<span class='status $status_class'>$status</span>";
                ?></td>
            </tr>
        </table>
        
        <h2>Enabled UFW Rules</h2>
        <pre><?php echo shell_exec('ufw status numbered'); ?></pre>
        
        <p><small>Generated on <?php echo date('Y-m-d H:i:s'); ?></small></p>
    </div>
</body>
</html>
EOL

# Summary
IP_ADDRESS=$(hostname -I | awk '{print $1}')
print_status "Installation Complete!"
echo "======================================================="
echo -e "${GREEN}LEMP Stack Installation Summary${NC}"
echo "======================================================="
echo -e "${CYAN}Server Information:${NC}"
echo "- IP Address: $IP_ADDRESS"
echo -e "${CYAN}Web Server:${NC}"
echo "- NGINX installed and running"
echo -e "${CYAN}Database:${NC}"
echo "- MariaDB installed and secured"
echo "- Root Password: $MYSQL_ROOT_PASSWORD"
echo "- Password saved to: /root/.mariadb_credentials"
echo -e "${CYAN}PHP:${NC}"
echo "- PHP versions 5.6, 7.0-7.4, 8.0-8.2 installed"
echo "- Default version set to 8.2"
echo "- PHP Version Switcher: /usr/local/bin/phpswitch"
echo -e "${CYAN}phpMyAdmin:${NC}"
echo "- Available at: http://$IP_ADDRESS/phpmyadmin"
echo "- Username: root"
echo "- Password: $MYSQL_ROOT_PASSWORD"
echo -e "${CYAN}Security:${NC}"
echo "- Fail2Ban configured for SSH and NGINX"
echo "- UFW enabled with rules for ports 22, 80, and 443"
echo -e "${CYAN}Testing:${NC}"
echo "- PHP info page: http://$IP_ADDRESS/info.php"
echo "- Server status: http://$IP_ADDRESS/versions.php"
echo "======================================================="
echo -e "${YELLOW}IMPORTANT: For security reasons, you should remove or restrict access${NC}"
echo -e "${YELLOW}to the info.php file after testing:${NC}"
echo "  rm /var/www/html/info.php"
echo "======================================================="
echo -e "${GREEN}Log file available at:${NC} $LOG_FILE"
echo ""

# Ask about root SSH access setup
log "Would you like to set up root SSH access? (y/n)"
read -r setup_ssh
if [[ "$setup_ssh" =~ ^[Yy]$ ]]; then
    setup_root_ssh
    log "Root SSH access has been set up. The server will now reboot in 10 seconds. Please login as root after reboot."
    log "Installation completed successfully!"
    sleep 10
    reboot
else
    log "Root SSH access setup skipped."
    
    # Suggest a reboot
    read -p "Would you like to reboot now to ensure all services start properly? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Rebooting system..."
        reboot
    else
        print_status "Reboot skipped. You may want to reboot later to ensure all services start properly."
    fi
    log "Installation completed successfully!"
fi

exit 0
