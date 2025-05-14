# Ubuntu Multi-PHP LEMP Stack Installer v.1.0

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive bash script to automatically install and configure a complete LEMP (Linux, NGINX, MariaDB, PHP) stack with multiple PHP versions on Ubuntu. Perfect for development environments or production servers that need to support applications requiring different PHP versions.

![LEMP Stack](https://img.shields.io/badge/LEMP-Stack-blue)
![Ubuntu](https://img.shields.io/badge/Ubuntu-Compatible-orange)
![PHP](https://img.shields.io/badge/PHP-Multi--Version-green)

## Features

- **Multiple PHP Versions**: Installs PHP 5.6, 7.0, 7.1, 7.2, 7.3, 7.4, 8.0, 8.1 and 8.2 simultaneously
- **Easy PHP Switching**: Includes a convenient command-line tool to switch between PHP versions
- **NGINX Web Server**: Installs and configures latest NGINX from Ondřej Surý's repository
- **MariaDB Database**: Installs and secures MariaDB server with automated configuration
- **phpMyAdmin**: Sets up web-based database management interface
- **Security Features**:
  - Fail2Ban for intrusion prevention (protects SSH, NGINX)
  - UFW Firewall pre-configured with sensible defaults (ports 22, 80, 443)
  - Secure MariaDB installation
- **Monitoring & Testing**: Creates testing pages for PHP info and server status

## Requirements

- A fresh installation of Ubuntu (18.04, 20.04, 22.04, or newer)
- Root privileges
- Internet connection

## Quick Start

1. Download the installer script:
```bash
wget https://raw.githubusercontent.com/script-php/lemp/main/installer.sh
```

2. Make it executable:
```bash
chmod +x installer.sh
```

3. Run the script as root:
```bash
sudo ./installer.sh
```

4. Follow the on-screen prompts to complete the installation.

## What Gets Installed

| Component | Details |
|-----------|---------|
| NGINX | Latest version from Ondřej Surý's repository |
| PHP | Versions 5.6, 7.0, 7.1, 7.2, 7.3, 7.4, 8.0, 8.1 and 8.2 with common extensions |
| MariaDB | Latest stable version |
| phpMyAdmin | Web interface for database management |
| Fail2Ban | Intrusion prevention system |
| UFW | Uncomplicated Firewall with pre-configured rules |

## PHP Version Management

After installation, you can switch between PHP versions using the included `phpswitch` command:

```bash
# List available PHP versions
phpswitch

# Switch to PHP 8.1
phpswitch 8.1

# Check current PHP version
php -v
```

The script will automatically configure NGINX to use the selected PHP version.

## Security Considerations

For production servers, consider:

1. Setting a strong password for MariaDB root user during installation

2. Disabling root SSH access if not needed:
```bash
# Edit SSH config
nano /etc/ssh/sshd_config

# Change this line
PermitRootLogin no

# Restart SSH
systemctl restart sshd
```

## Customization

You can easily customize the installer by editing the script:

- To install additional PHP versions, modify the `php_versions` array
- To add more PHP extensions, update the apt-get install commands
- To modify firewall rules, update the UFW section

## Troubleshooting

If you encounter issues during installation:

1. Check the log file at `/var/log/lemp_installer.log`
2. Verify all services are running:
```bash
systemctl status nginx
systemctl status mariadb
systemctl status php*-fpm
```

3. Check NGINX configuration:
```bash
nginx -t
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Ondřej Surý](https://launchpad.net/~ondrej) for maintaining the PHP and NGINX repositories
- The LEMP stack community for documentation and best practices

## Disclaimer

This script is provided "as is", without warranty of any kind. Use at your own risk.
