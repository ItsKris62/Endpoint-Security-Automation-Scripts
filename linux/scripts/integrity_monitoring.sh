#!/bin/bash

# --- Configuration ---
LOG_TAG="integrity-monitoring"
LOCK_FILE="/var/run/integrity_monitoring.lock"
MAX_LOCK_AGE=3600
OUTPUT_DIR="/var/log/security"
OUTPUT_FILE="${OUTPUT_DIR}/integrity_check.json"
BASELINE_DIR="/etc/security/baseline"
SYSLOG_ENABLED=true
JSON_OUTPUT=true

# Files and directories to monitor (configure based on your needs)
MONITOR_PATHS=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/group"
    "/etc/sudoers"
    "/etc/ssh/sshd_config"
    "/bin"
    "/sbin"
    "/usr/bin"
    "/usr/sbin"
    "/usr/local/bin"
    "/usr/local/sbin"
)

# --- Initialize Environment ---
set -euo pipefail
IFS=$'\n\t'

# --- Import Common Functions ---
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
    
    if [ ! -d "$BASELINE_DIR" ]; then
        mkdir -p "$BASELINE_DIR"
        chmod 700 "$BASELINE_DIR"
        log "INFO" "Created baseline directory: ${BASELINE_DIR}"
    fi
}

# --- Generate File Hash ---
generate_hash() {
    local file_path=$1
    local algorithm=${2:-sha256}
    
    if [ ! -f "$file_path" ] && [ ! -d "$file_path" ]; then
        log "WARN" "Path does not exist: ${file_path}"
        return 1
    fi
    
    case $algorithm in
        "md5")
            md5sum "$file_path" 2>/dev/null | awk '{print $1}'
            ;;
        "sha1")
            sha1sum "$file_path" 2>/dev/null | awk '{print $1}'
            ;;
        "sha256")
            sha256sum "$file_path" 2>/dev/null | awk '{print $1}'
            ;;
        *)
            log "ERROR" "Unsupported hash algorithm: ${algorithm}"
            return 1
            ;;
    esac
    
    return $?
}

# --- Create Baseline ---
create_baseline() {
    local baseline_file="${BASELINE_DIR}/baseline_$(date +%Y%m%d_%H%M%S).json"
    local changes_detected=0
    local file_count=0
    
    log "INFO" "Creating new integrity baseline: ${baseline_file}"
    
    # Start JSON output
    echo '{"timestamp": "'$(date +%s)'", "hostname": "'$(hostname)'", "baseline": [' > "$baseline_file"
    
    for path in "${MONITOR_PATHS[@]}"; do
        if [ ! -e "$path" ]; then
            log "WARN" "Path does not exist: ${path}"
            continue
        fi
        
        if [ -f "$path" ]; then
            # Process single file
            local hash=$(generate_hash "$path" "sha256")
            if [ $? -eq 0 ]; then
                echo "{\"path\": \"$path\", \"hash\": \"$hash\", \"type\": \"file\", \"permissions\": \"$(stat -c %a "$path")\"}," >> "$baseline_file"
                ((file_count++))
            else
                log "WARN" "Failed to generate hash for: ${path}"
            fi
        elif [ -d "$path" ]; then
            # Process directory recursively
            while IFS= read -r -d '' file; do
                local hash=$(generate_hash "$file" "sha256")
                if [ $? -eq 0 ]; then
                    echo "{\"path\": \"$file\", \"hash\": \"$hash\", \"type\": \"file\", \"permissions\": \"$(stat -c %a "$file")\"}," >> "$baseline_file"
                    ((file_count++))
                else
                    log "WARN" "Failed to generate hash for: ${file}"
                fi
            done < <(find "$path" -type f -print0 2>/dev/null)
        fi
    done
    
    # Remove trailing comma and close JSON
    sed -i '$ s/,$//' "$baseline_file"
    echo ']}' >> "$baseline_file"
    
    # Create symlink to latest baseline
    ln -sf "$baseline_file" "${BASELINE_DIR}/baseline_latest.json"
    
    log "INFO" "Baseline created with ${file_count} files: ${baseline_file}"
}

# --- Verify Integrity Against Baseline ---
verify_integrity() {
    local baseline_file="${BASELINE_DIR}/baseline_latest.json"
    local changes_detected=0
    local files_checked=0
    
    if [ ! -f "$baseline_file" ]; then
        log "ERROR" "No baseline found. Please create a baseline first."
        return 1
    fi
    
    log "INFO" "Verifying integrity against baseline: ${baseline_file}"
    
    # Extract baseline data
    local baseline_data=$(jq -c '.baseline[]' "$baseline_file" 2>/dev/null)
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to parse baseline file"
        return 1
    fi
    
    # Start JSON output for results
    local timestamp=$(date +%s)
    local hostname=$(hostname)
    local result_file="${OUTPUT_DIR}/integrity_check_${timestamp}.json"
    
    echo "{\"timestamp\": \"$timestamp\", \"hostname\": \"$hostname\", \"changes\": [" > "$result_file"
    
    # Check each file in baseline
    while IFS= read -r line; do
        local path=$(echo "$line" | jq -r '.path')
        local expected_hash=$(echo "$line" | jq -r '.hash')
        local expected_perms=$(echo "$line" | jq -r '.permissions')
        
        # Skip if file doesn't exist (it was deleted)
        if [ ! -e "$path" ]; then
            echo "{\"path\": \"$path\", \"change\": \"file_deleted\"}," >> "$result_file"
            ((changes_detected++))
            continue
        fi
        
        # Check permissions
        local current_perms=$(stat -c %a "$path")
        if [ "$current_perms" != "$expected_perms" ]; then
            echo "{\"path\": \"$path\", \"change\": \"permissions_changed\", \"expected\": \"$expected_perms\", \"current\": \"$current_perms\"}," >> "$result_file"
            ((changes_detected++))
        fi
        
        # Check hash
        local current_hash=$(generate_hash "$path" "sha256")
        if [ "$current_hash" != "$expected_hash" ]; then
            echo "{\"path\": \"$path\", \"change\": \"content_modified\", \"expected_hash\": \"$expected_hash\", \"current_hash\": \"$current_hash\"}," >> "$result_file"
            ((changes_detected++))
        fi
        
        ((files_checked++))
    done <<< "$baseline_data"
    
    # Remove trailing comma and close JSON
    sed -i '$ s/,$//' "$result_file"
    echo "], \"files_checked\": $files_checked, \"changes_detected\": $changes_detected, \"status\": \"success\"}" >> "$result_file"
    
    # Create symlink to latest result
    ln -sf "$result_file" "$OUTPUT_FILE"
    
    if [ $changes_detected -gt 0 ]; then
        log "WARN" "Integrity check completed. Changes detected: ${changes_detected}"
    else
        log "INFO" "Integrity check completed. No changes detected."
    fi
    
    return $changes_detected
}

# --- Main Execution ---
main() {
    local action=${1:-verify}
    
    log "INFO" "Starting integrity monitoring (action: ${action})"
    
    # Set up trap for cleanup on exit
    trap cleanup EXIT INT TERM
    
    # Pre-flight checks
    check_root
    check_lock
    ensure_output_dir
    
    case $action in
        "create")
            create_baseline
            ;;
        "verify")
            verify_integrity
            local changes=$?
            exit $changes  # Exit with number of changes for monitoring systems
            ;;
        *)
            log "ERROR" "Invalid action: ${action}. Use 'create' or 'verify'."
            exit 1
            ;;
    esac
}

# Execute main function with optional parameter
main "$@"