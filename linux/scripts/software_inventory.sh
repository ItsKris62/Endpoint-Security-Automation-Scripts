#!/bin/bash

# --- Configuration ---
LOG_TAG="software-inventory"
LOCK_FILE="/var/run/software_inventory.lock"
MAX_LOCK_AGE=3600
OUTPUT_DIR="/var/log/security"
OUTPUT_FILE="${OUTPUT_DIR}/software_inventory.json"
SYSLOG_ENABLED=true
JSON_OUTPUT=true

# --- Initialize Environment ---
set -euo pipefail
IFS=$'\n\t'

# --- Import Common Functions ---
# In a real implementation, you'd source common functions from a shared file
log() {
    local level=$1
    local message=$2
    local timestamp=$(date +"%Y-%m-%d %T %Z")
    
    echo "[${timestamp}] [${level}] ${message}"
    
    if [ "$SYSLOG_ENABLED" = true ]; then
        logger -t "$LOG_TAG" -p "user.${level}" "$message"
    fi
}

cleanup() {
    local exit_code=$?
    
    if [ -f "$LOCK_FILE" ]; then
        rm -f "$LOCK_FILE"
        log "INFO" "Removed lock file: ${LOCK_FILE}"
    fi
    
    exit $exit_code
}

check_lock() {
    if [ -f "$LOCK_FILE" ]; then
        local lock_age=$(($(date +%s) - $(stat -c %Y "$LOCK_FILE")))
        
        if [ $lock_age -gt $MAX_LOCK_AGE ]; then
            log "WARN" "Stale lock file found (age: ${lock_age}s). Removing and continuing."
            rm -f "$LOCK_FILE"
        else
            log "ERROR" "Script already running (lock file exists: ${LOCK_FILE}). Exiting."
            exit 1
        fi
    fi
    
    touch "$LOCK_FILE"
    log "INFO" "Created lock file: ${LOCK_FILE}"
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "ERROR" "This script must be run as root. Exiting."
        exit 1
    fi
}

ensure_output_dir() {
    if [ ! -d "$OUTPUT_DIR" ]; then
        mkdir -p "$OUTPUT_DIR"
        chmod 700 "$OUTPUT_DIR"
        log "INFO" "Created output directory: ${OUTPUT_DIR}"
    fi
}

# --- Get Installed Packages ---
get_installed_packages() {
    local pkg_mgr=$1
    local packages=""
    
    log "INFO" "Retrieving installed packages using ${pkg_mgr}"
    
    case $pkg_mgr in
        "apt")
            packages=$(dpkg-query -W -f='${Package} ${Version} ${Architecture}\n' 2>/dev/null | \
                      awk '{printf "{\"name\": \"%s\", \"version\": \"%s\", \"architecture\": \"%s\"},", $1, $2, $3}')
            ;;
        "yum"|"dnf")
            packages=$(rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n' 2>/dev/null | \
                      awk '{printf "{\"name\": \"%s\", \"version\": \"%s\", \"architecture\": \"%s\"},", $1, $2, $3}')
            ;;
        "zypper")
            packages=$(rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n' 2>/dev/null | \
                      awk '{printf "{\"name\": \"%s\", \"version\": \"%s\", \"architecture\": \"%s\"},", $1, $2, $3}')
            ;;
        *)
            log "ERROR" "Unsupported package manager: ${pkg_mgr}"
            return 1
            ;;
    esac
    
    # Remove trailing comma
    packages=${packages%,}
    echo "$packages"
}

# --- Detect Package Manager ---
detect_package_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v yum >/dev/null 2>&1; then
        echo "yum"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v zypper >/dev/null 2>&1; then
        echo "zypper"
    else
        log "ERROR" "Unsupported package manager. Exiting."
        exit 1
    fi
}

# --- Generate Software Inventory ---
generate_inventory() {
    local pkg_mgr=$1
    
    # Get package list
    local packages=$(get_installed_packages "$pkg_mgr")
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    # Get system information
    local os_name=$(grep '^NAME=' /etc/os-release | cut -d= -f2 | tr -d '"')
    local os_version=$(grep '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    local kernel_version=$(uname -r)
    local hostname=$(hostname)
    local timestamp=$(date +%s)
    
    # Create JSON output
    cat > "$OUTPUT_FILE" << EOF
{
  "timestamp": "$timestamp",
  "hostname": "$hostname",
  "check_type": "software_inventory",
  "operating_system": {
    "name": "$os_name",
    "version": "$os_version",
    "kernel": "$kernel_version"
  },
  "package_manager": "$pkg_mgr",
  "package_count": $(echo "$packages" | tr -cd ',' | wc -c),
  "packages": [$packages],
  "status": "success"
}
EOF
    
    log "INFO" "Software inventory written to ${OUTPUT_FILE}"
}

# --- Main Execution ---
main() {
    log "INFO" "Starting software inventory check"
    
    # Set up trap for cleanup on exit
    trap cleanup EXIT INT TERM
    
    # Pre-flight checks
    check_root
    check_lock
    ensure_output_dir
    
    # Detect package manager
    local pkg_mgr=$(detect_package_manager)
    log "INFO" "Detected package manager: ${pkg_mgr}"
    
    # Generate inventory
    if generate_inventory "$pkg_mgr"; then
        log "INFO" "Software inventory completed successfully"
    else
        log "ERROR" "Failed to generate software inventory"
        exit 1
    fi
}

# Execute main function
main "$@"