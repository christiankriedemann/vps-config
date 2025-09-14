#!/bin/bash

# ============================================================================
#                     DEBIAN BACKUP-MANAGER SETUP SCRIPT
#                    Local Backups with S3-Ready Configuration
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Logging
log_success() { echo -e "${GREEN}✓${NC} $1"; }
log_error() { echo -e "${RED}✗${NC} $1"; }
log_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
log_info() { echo -e "${CYAN}ℹ${NC} $1"; }

# Check root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root"
    exit 1
fi

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}                    ${BOLD}DEBIAN BACKUP-MANAGER SETUP${NC}"
echo -e "${BLUE}                 Incremental Backups with Rotation${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ============= CHECK EXISTING SETUP =============
log_info "Checking for existing backup configuration..."

if [ -f /etc/backup-manager.conf ]; then
    log_warning "Backup-manager is already configured!"
    echo ""
    echo -e "${YELLOW}Configuration file exists: /etc/backup-manager.conf${NC}"
    echo ""
    read -p "Skip backup setup to keep existing configuration? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Keeping existing backup configuration"
        exit 0
    fi

    # Backup existing config
    cp /etc/backup-manager.conf "/etc/backup-manager.conf.backup.$(date +%Y%m%d_%H%M%S)"
    log_success "Backed up existing configuration"
fi

# ============= INSTALL BACKUP-MANAGER =============
log_info "Installing backup-manager..."

if dpkg -l | grep -q "^ii  backup-manager"; then
    log_success "backup-manager already installed"
else
    apt-get update
    apt-get install -y backup-manager || {
        log_error "Failed to install backup-manager"
        exit 1
    }
    log_success "backup-manager installed"
fi

# ============= CONFIGURE BACKUP-MANAGER =============
log_info "Configuring backup-manager..."

cat > /etc/backup-manager.conf << 'EOF'
##############################################################
# Backup Manager Configuration File
#
# * Local backup to /backup with rotation
# * Ready for S3/SSH upload extension
##############################################################

# Repository - Where to store backups
export BM_REPOSITORY_ROOT="/backup"

# Secure the repository
export BM_REPOSITORY_SECURE="true"
export BM_REPOSITORY_USER="root"
export BM_REPOSITORY_GROUP="root"
export BM_REPOSITORY_CHMOD="700"

##############################################################
# Archives configuration
##############################################################

# Archive method(s) to use
# tarball: tar archives
# tarball-incremental: incremental tar archives
# mysql: MySQL dumps
# pgsql: PostgreSQL dumps
export BM_ARCHIVE_METHOD="tarball-incremental"

# Archive name prefix
export BM_ARCHIVE_PREFIX="$(hostname -s)"

# Archive TTL (Time To Live) - days to keep archives
export BM_ARCHIVE_TTL="30"

# Purge duplicates (same MD5 sum)
export BM_ARCHIVE_PURGEDUPS="true"

# Archives compression type (bzip2, gzip, xz, lzma, none)
export BM_TARBALL_FILETYPE="gzip"

# Directories to backup (space separated)
export BM_TARBALL_DIRECTORIES="/etc /root /home /var/www /opt/vps-config /usr/local/bin"

# Exclude patterns (one per line in file)
export BM_TARBALL_BLACKLIST="/etc/backup-manager.blacklist"

# Incremental backup settings
export BM_TARBALLINC_MASTERDATETYPE="weekly"
export BM_TARBALLINC_MASTERDATEVALUE="1"  # Monday for weekly

##############################################################
# MySQL Configuration (if MySQL is installed)
##############################################################

# Backup MySQL?
export BM_MYSQL="false"

# MySQL settings (will be auto-detected if MySQL is installed)
export BM_MYSQL_ADMINLOGIN="root"
export BM_MYSQL_ADMINPASS=""
export BM_MYSQL_HOST="localhost"
export BM_MYSQL_PORT="3306"

# Databases to backup (all for all databases)
export BM_MYSQL_DATABASES="all"

# MySQL backup method
export BM_MYSQL_FILETYPE="bzip2"
export BM_MYSQL_SAFEDUMPS="true"

##############################################################
# PostgreSQL Configuration (if PostgreSQL is installed)
##############################################################

# Backup PostgreSQL?
export BM_PGSQL="false"

# PostgreSQL settings
export BM_PGSQL_ADMINLOGIN="postgres"
export BM_PGSQL_HOST="localhost"
export BM_PGSQL_PORT="5432"

# Databases to backup
export BM_PGSQL_DATABASES="all"

# PostgreSQL backup method
export BM_PGSQL_FILETYPE="bzip2"

##############################################################
# Upload configuration (disabled by default)
##############################################################

# Upload method (none, ssh, s3, ftp)
export BM_UPLOAD_METHOD="none"

# S3 Configuration (for future use)
# export BM_UPLOAD_METHOD="s3"
# export BM_UPLOAD_S3_DESTINATION="s3://your-bucket/backups"
# export BM_UPLOAD_S3_ACCESS_KEY="your-access-key"
# export BM_UPLOAD_S3_SECRET_KEY="your-secret-key"
# export BM_UPLOAD_S3_PURGE="true"
# export BM_UPLOAD_S3_TTL="7"

# SSH Configuration (for future use)
# export BM_UPLOAD_METHOD="ssh"
# export BM_UPLOAD_SSH_HOSTS="backup-server.example.com"
# export BM_UPLOAD_SSH_PORT="22"
# export BM_UPLOAD_SSH_USER="backup"
# export BM_UPLOAD_SSH_KEY="/root/.ssh/id_rsa"
# export BM_UPLOAD_SSH_DESTINATION="/remote/backup/path"
# export BM_UPLOAD_SSH_PURGE="true"
# export BM_UPLOAD_SSH_TTL="7"

##############################################################
# Advanced settings
##############################################################

# Pre and post backup hooks
export BM_PRE_BACKUP_COMMAND=""
export BM_POST_BACKUP_COMMAND=""

# Burning configuration (disabled)
export BM_BURNING_METHOD="none"

# Log level (info, warning, error)
export BM_LOGGER_LEVEL="info"

# Syslog facility
export BM_LOGGER_FACILITY="user"

# Nice level for backup process
export BM_ARCHIVE_NICE_LEVEL="10"

# Verbosity
export BM_VERBOSE="false"

##############################################################
# End of Backup Manager Configuration
##############################################################
EOF

log_success "Created backup-manager configuration"

# ============= CREATE BLACKLIST FILE =============
log_info "Creating exclude patterns..."

cat > /etc/backup-manager.blacklist << 'EOF'
*.tmp
*.cache
*.log
*.pid
*.lock
*.sock
/var/cache/*
/var/tmp/*
/tmp/*
/proc/*
/sys/*
/dev/*
/run/*
/mnt/*
/media/*
node_modules/
.git/objects/
*.swp
*~
.Trash*
lost+found/
EOF

log_success "Created exclude patterns"

# ============= CHECK FOR DATABASES =============
log_info "Checking for database servers..."

# MySQL/MariaDB detection
if command -v mysql &>/dev/null || command -v mariadb &>/dev/null; then
    log_success "MySQL/MariaDB detected - enabling MySQL backups"
    sed -i 's/export BM_MYSQL="false"/export BM_MYSQL="true"/' /etc/backup-manager.conf

    # Try to set up passwordless access for root
    if [ -f /root/.my.cnf ]; then
        log_success "MySQL credentials file exists"
    else
        log_warning "Consider creating /root/.my.cnf for passwordless MySQL backups"
        echo -e "${YELLOW}Example /root/.my.cnf:${NC}"
        echo "[client]"
        echo "user=root"
        echo "password=your-mysql-root-password"
    fi
fi

# PostgreSQL detection
if command -v psql &>/dev/null; then
    log_success "PostgreSQL detected - enabling PostgreSQL backups"
    sed -i 's/export BM_PGSQL="false"/export BM_PGSQL="true"/' /etc/backup-manager.conf
fi

# Docker volumes detection
if [ -d /var/lib/docker/volumes ] && [ "$(ls -A /var/lib/docker/volumes 2>/dev/null)" ]; then
    log_success "Docker volumes detected - adding to backup"
    sed -i 's|export BM_TARBALL_DIRECTORIES="|export BM_TARBALL_DIRECTORIES="/var/lib/docker/volumes |' /etc/backup-manager.conf
fi

# ============= CREATE BACKUP DIRECTORY =============
log_info "Setting up backup directory..."

if [ ! -d /backup ]; then
    mkdir -p /backup
    chmod 700 /backup
    log_success "Created backup directory: /backup"
else
    log_success "Backup directory exists: /backup"
fi

# ============= CREATE CRON JOB =============
log_info "Setting up automated backup schedule..."

cat > /etc/cron.d/backup-manager << 'EOF'
# Backup Manager cron job
# Daily backup at 2:00 AM
0 2 * * * root /usr/sbin/backup-manager --verbose >/var/log/backup-manager.log 2>&1
EOF

log_success "Created daily backup schedule (2:00 AM)"

# ============= CREATE MANAGEMENT SCRIPT =============
log_info "Creating backup management commands..."

cat > /usr/local/bin/backup-status << 'EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

BACKUP_DIR="/backup"

case "$1" in
    status)
        echo -e "${CYAN}=== Backup Status ===${NC}"
        echo ""

        # Disk usage
        echo -e "${CYAN}Backup Directory:${NC}"
        df -h "$BACKUP_DIR"
        echo ""

        # List backups
        echo -e "${CYAN}Recent Backups:${NC}"
        if [ -d "$BACKUP_DIR" ] && [ "$(ls -A $BACKUP_DIR 2>/dev/null)" ]; then
            ls -lht "$BACKUP_DIR" | head -10
        else
            echo -e "${RED}No backups found${NC}"
        fi
        echo ""

        # Check last backup
        if [ -f /var/log/backup-manager.log ]; then
            echo -e "${CYAN}Last Backup Log:${NC}"
            tail -5 /var/log/backup-manager.log
        fi
        ;;

    run)
        echo "Running manual backup..."
        /usr/sbin/backup-manager --verbose
        echo -e "${GREEN}✓ Backup completed${NC}"
        ;;

    list)
        echo -e "${CYAN}=== Available Backups ===${NC}"
        if [ -d "$BACKUP_DIR" ]; then
            for file in "$BACKUP_DIR"/*.tar.gz "$BACKUP_DIR"/*.sql.bz2 2>/dev/null; do
                [ -f "$file" ] && echo "$(basename $file) - $(du -h $file | cut -f1)"
            done
        else
            echo "No backups found"
        fi
        ;;

    extract)
        if [ -z "$2" ]; then
            echo "Usage: backup-status extract <archive.tar.gz>"
            echo ""
            echo "Available archives:"
            ls "$BACKUP_DIR"/*.tar.gz 2>/dev/null | xargs -n1 basename
            exit 1
        fi

        archive="$BACKUP_DIR/$2"
        if [ -f "$archive" ]; then
            extract_dir="/tmp/backup-extract-$(date +%s)"
            mkdir -p "$extract_dir"
            echo "Extracting to $extract_dir..."
            tar -xzf "$archive" -C "$extract_dir"
            echo -e "${GREEN}✓ Extracted to: $extract_dir${NC}"
            echo "Browse with: cd $extract_dir"
        else
            echo -e "${RED}Archive not found: $2${NC}"
        fi
        ;;

    clean)
        echo "Cleaning old backups (keeping last 30 days)..."
        find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete
        find "$BACKUP_DIR" -name "*.sql.bz2" -mtime +30 -delete
        echo -e "${GREEN}✓ Old backups cleaned${NC}"
        ;;

    size)
        echo -e "${CYAN}=== Backup Sizes ===${NC}"
        if [ -d "$BACKUP_DIR" ]; then
            echo "Individual backups:"
            du -sh "$BACKUP_DIR"/* 2>/dev/null | sort -h | tail -10
            echo ""
            echo -e "${CYAN}Total size:${NC}"
            du -sh "$BACKUP_DIR"
        fi
        ;;

    config)
        echo -e "${CYAN}=== Backup Configuration ===${NC}"
        grep -E "^export BM_" /etc/backup-manager.conf | grep -v PASSWORD | head -20
        ;;

    test)
        echo "Testing backup configuration..."
        /usr/sbin/backup-manager --test
        ;;

    *)
        echo "Usage: backup-status {status|run|list|extract|clean|size|config|test}"
        echo ""
        echo "Commands:"
        echo "  status  - Show backup status"
        echo "  run     - Run manual backup"
        echo "  list    - List available backups"
        echo "  extract - Extract backup archive"
        echo "  clean   - Remove old backups"
        echo "  size    - Show backup sizes"
        echo "  config  - Show configuration"
        echo "  test    - Test configuration"
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/backup-status
log_success "Created backup-status command"

# ============= RUN INITIAL BACKUP =============
echo ""
log_info "Running initial backup..."
echo -e "${YELLOW}This may take a few minutes...${NC}"

if /usr/sbin/backup-manager; then
    log_success "Initial backup completed"

    # Show created files
    echo ""
    echo -e "${CYAN}Created backups:${NC}"
    ls -lh /backup/*.tar.gz 2>/dev/null | tail -5
else
    log_warning "Initial backup had issues (check logs)"
fi

# ============= SUMMARY =============
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}              ✓ BACKUP-MANAGER CONFIGURED SUCCESSFULLY${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BOLD}Configuration:${NC}"
echo -e "  • Backup Directory: ${CYAN}/backup${NC}"
echo -e "  • Backup Method: ${GREEN}Incremental tar archives${NC}"
echo -e "  • Schedule: ${GREEN}Daily at 2:00 AM${NC}"
echo -e "  • Retention: ${GREEN}30 days${NC}"
echo -e "  • Compression: ${GREEN}gzip${NC}"
echo ""
echo -e "${BOLD}Backup Sources:${NC}"
echo -e "  • /etc (System configuration)"
echo -e "  • /root (Root home)"
echo -e "  • /home (User homes)"
echo -e "  • /var/www (Websites)"
echo -e "  • /opt/vps-config (VPS scripts)"
echo -e "  • /usr/local/bin (Custom scripts)"
if command -v mysql &>/dev/null; then
    echo -e "  • ${GREEN}MySQL databases${NC}"
fi
if command -v psql &>/dev/null; then
    echo -e "  • ${GREEN}PostgreSQL databases${NC}"
fi
if [ -d /var/lib/docker/volumes ]; then
    echo -e "  • ${GREEN}Docker volumes${NC}"
fi
echo ""
echo -e "${BOLD}Management Commands:${NC}"
echo -e "  ${CYAN}backup-status status${NC}  - Show backup status"
echo -e "  ${CYAN}backup-status run${NC}     - Run manual backup"
echo -e "  ${CYAN}backup-status list${NC}    - List backups"
echo -e "  ${CYAN}backup-status extract${NC} - Extract backup archive"
echo -e "  ${CYAN}backup-status size${NC}    - Show sizes"
echo ""
echo -e "${BOLD}Configuration Files:${NC}"
echo -e "  • /etc/backup-manager.conf - Main configuration"
echo -e "  • /etc/backup-manager.blacklist - Exclude patterns"
echo ""
echo -e "${YELLOW}S3/SSH Upload:${NC}"
echo -e "  To enable S3 or SSH uploads, edit /etc/backup-manager.conf"
echo -e "  and modify the BM_UPLOAD_* settings"
echo ""
echo -e "${GREEN}✓ Backup system is active and will run daily at 2:00 AM${NC}"
echo ""

# Show status
backup-status status

exit 0
