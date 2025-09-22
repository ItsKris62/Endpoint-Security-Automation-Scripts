#!/bin/bash

# --- Configuration ---
# Externalize these to a config file in production
LOG_TAG="patch-compliance"
LOCK_FILE="/var/run/patch_compliance.lock"
MAX_LOCK_AGE=3600 # 1 hour in seconds
OUTPUT_DIR="/var/log/security"
OUTPUT_FILE="${OUTPUT_DIR}/patch_compliance.json"
SYSLOG_ENABLED=true
JSON_OUTPUT=true

# --- Initialize Environment ---
set -euo pipefail # Exit on error, undefined variable, or pipe failure
IFS=$'\n\t'       # Set Internal Field Separator for safer word splitting

# --- Logging Function ---
log() {
    local level=$1
    local message=$2
    local timestamp=$(date +"%Y-%m-%d %T %Z")
    
    # Console output
    echo "[${timestamp}] [${level}] ${message}"
    
    # Syslog output if enabled
    if [ "$SYSLOG_ENABLED" = true ]; then
        logger -t "$LOG_TAG" -p "user.${level}" "$message"
    fi
}

# --- Cleanup Function ---
cleanup() {
    local exit_code=$?
    
    # Remove lock file on exit
    if [ -f "$LOCK_FILE" ]; then
        rm -f "$LOCK_FILE"
        log "INFO" "Removed lock file: ${LOCK_FILE}"
    fi
    
    # Exit with proper code
    if [ $exit_code -ne 0 ]; then
        log "ERROR" "Script exited with error code: $exit_code"
    else
        log "INFO" "Script completed successfully"
    fi
    
    exit $exit_code
}

# --- Check Lock File ---
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
    
    # Create lock file
    touch "$LOCK_FILE"
    log "INFO" "Created lock file: ${LOCK_FILE}"
}

# --- Check for Root Privileges ---
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "ERROR" "This script must be run as root. Exiting."
        exit 1
    fi
}

# --- Ensure Output Directory Exists ---
ensure_output_dir() {
    if [ ! -d "$OUTPUT_DIR" ]; then
        mkdir -p "$OUTPUT_DIR"
        chmod 700 "$OUTPUT_DIR"
        log "INFO" "Created output directory: ${OUTPUT_DIR}"
    fi
}

# --- Check Package Manager ---
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

# --- Check for Security Updates ---
check_updates() {
    local pkg_mgr=$1
    local updates=()
    local security_updates=()
    
    log "INFO" "Checking for updates using ${pkg_mgr}"
    
    case $pkg_mgr in
        "apt")
            # Update package lists
            if ! apt-get update > /dev/null 2>&1; then
                log "ERROR" "Failed to update package lists"
                return 1
            fi
            
            # Check for updates
            updates=$(apt-get upgrade --simulate 2>/dev/null | grep -E '^Inst' | awk '{print $2}' | tr '\n' ' ')
            security_updates=$(apt-get upgrade --simulate 2>/dev/null | grep -E '^Inst' | grep -i security | awk '{print $2}' | tr '\n' ' ')
            ;;
        "yum"|"dnf")
            # Check for updates
            updates=$(yum check-update --quiet 2>/dev/null | grep -E '^\w' | awk '{print $1}' | tr '\n' ' ' || true)
            security_updates=$(yum check-update --security --quiet 2>/dev/null | grep -E '^\w' | awk '{print $1}' | tr '\n' ' ' || true)
            ;;
        "zypper")
            # Refresh repositories
            if ! zypper refresh > /dev/null 2>&1; then
                log "ERROR" "Failed to refresh repositories"
                return 1
            fi
            
            # Check for updates
            updates=$(zypper list-updates 2>/dev/null | grep -E '^v|\|' | awk '{print $3}' | tr '\n' ' ' || true)
            security_updates=$(zypper list-patches --category security 2>/dev/null | grep -E '^\d' | awk '{print $2}' | tr '\n' ' ' || true)
            ;;
    esac
    
    # Count updates
    local update_count=$(echo $updates | wc -w)
    local security_count=$(echo $security_updates | wc -w)
    
    # Prepare JSON output if enabled
    if [ "$JSON_OUTPUT" = true ]; then
        local timestamp=$(date +%s)
        local hostname=$(hostname)
        
        # Create JSON output
        cat > "$OUTPUT_FILE" << EOF
{
  "timestamp": "$timestamp",
  "hostname": "$hostname",
  "check_type": "patch_compliance",
  "package_manager": "$pkg_mgr",
  "updates_available": $update_count,
  "security_updates_available": $security_count,
  "updates_list": [$(echo $updates | sed 's/ /", "/g' | sed 's/^/"/' | sed 's/$/"/')],
  "security_updates_list": [$(echo $security_updates | sed 's/ /", "/g' | sed 's/^/"/' | sed 's/$/"/')],
  "status": "success"
}
EOF
        
        log "INFO" "Results written to ${OUTPUT_FILE}"
    else
        # Traditional output
        log "INFO" "Available updates: ${update_count}"
        log "INFO" "Security updates: ${security_count}"
        
        if [ $update_count -gt 0 ]; then
            log "INFO" "Update list: ${updates}"
        fi
        
        if [ $security_count -gt 0 ]; then
            log "WARN" "Security updates needed: ${security_updates}"
        fi
    fi
    
    # Return security update count for monitoring systems
    return $security_count
}

# --- Main Execution ---
main() {
    log "INFO" "Starting patch compliance check"
    
    # Set up trap for cleanup on exit
    trap cleanup EXIT INT TERM
    
    # Pre-flight checks
    check_root
    check_lock
    ensure_output_dir
    
    # Detect package manager
    local pkg_mgr=$(detect_package_manager)
    log "INFO" "Detected package manager: ${pkg_mgr}"
    
    # Check for updates
    if check_updates "$pkg_mgr"; then
        local security_count=$?
        if [ $security_count -gt 0 ]; then
            log "WARN" "${security_count} security updates available"
        else
            log "INFO" "System is up to date"
        fi
    else
        log "ERROR" "Failed to check for updates"
        exit 1
    fi
}

# Execute main function
main "$@"