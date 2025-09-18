#!/bin/bash
#
# Script Name: mac-os.sh
# Description: Manages Netskope CA certificates, creates a combined CA bundle, and automatically configures SSL environment variables
# Author: r4reetik
#
# Usage: curl -fsSL <endpoint> | sudo bash -s -- [options]
# Or: ./mac-os.sh [options]
# Options:
#   -h, --help              Show this help message
#   -r, --revert            Revert Netskope certificates and clean up configuration
#

set -uo pipefail

# Raw cetificates of Netskope
readonly CA_CERT="-----BEGIN CERTIFICATE-----
MIIEVTCCAz2gAwIBAgIUKJFS51D2kqQ/ayfubXi/2J0Im1MwDQYJKoZIhvcNAQEL
BQAwgZ4xJTAjBgkqhkiG9w0BCQEMFmNlcnRhZG1pbkBuZXRza29wZS5jb20xGzAZ
BgNVBAMMEiouc2luMi5nb3Nrb3BlLmNvbTESMBAGA1UECwwJY2VydGFkbWluMRYw
FAYDVQQKDA1OZXRza29wZSBJbmMuMRIwEAYDVQQHDAlTaW5nYXBvcmUxCzAJBgNV
BAgMAlNHMQswCQYDVQQGDAJTRzAeFw0yNTAxMDIxMDUxMDlaFw0zNDEyMzExMDUx
MDlaMIGjMSUwIwYJKoZIhvcNAQkBDBZjZXJ0YWRtaW5AbmV0c2tvcGUuY29tMSEw
HwYDVQQDDBhjYS5jYXNoZ3JhaWwuZ29za29wZS5jb20xKTAnBgNVBAsMIGJlOTUy
MjAyZWZlZWI2M2Y1NDdiNGVkM2RmYmM0NDcwMRIwEAYDVQQKDAljYXNoZ3JhaWwx
CzAJBgNVBAgMAklOMQswCQYDVQQGDAJJTjCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAMI/0jpdnqTpaRMruoROZXnZkslO1+HpxAoIP4TVT5m2671cythA
a1f71m1HFYj6636fk78b4Uwlz4euGpvgB0HO7zm4aUGdx+Bl56yUcNosswO7c7Hb
v/f5OmptyZY+07ZrmsvMhnh0r2DgpSQXODdPTMhvY2EG6+SETaNxmhVCyGix1745
BKRlSgMs8SybSi1IAV+poVL6SMV8e6BCakncocWTzeB2TplE/zzhMm0mYovu8DpQ
nuoeV7fQEKafMl9AsoDhCNXsysKJigKO8EOVYtquLF9vyLRjR7mv9AyzpIYbDOxH
GQSos8oozmGY4LsHnkdvdCHFrXSB7A5YiCsCAwEAAaOBgzCBgDASBgNVHRMBAf8E
CDAGAQH/AgEBMAsGA1UdDwQEAwIBpjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYB
BQUHAwIwHQYDVR0OBBYEFLzEJ6kDh3Wcoe0D/Pnz5Us8E1d+MB8GA1UdIwQYMBaA
FKHpWcD/voOMAAy5jQJyB0Jg0DAYMA0GCSqGSIb3DQEBCwUAA4IBAQBv+mfbVWEB
UQDCkYPFzzKq4+JZqIYxdW24CcZEgkjDljW8xItf5v6YdHtwKI6yzJwCrPV6bN+n
81s9PKHQ+RFMAXNnxikmjJaZi/8RVz8fwf7ExAHwXQzBYXBZCiX6s7ciWShBBbUc
1jeod8wXktq+QbDJkPFtkEkTlpHoT8pt0LQ9EON7QhYele9cffKTYeEmBCXH08pc
xudq2dcqDQNEgtTepibxoPUXZAXk2z9Yj0dzX+e5rrgT1GNtboLriWufQcjdtuna
5kVvqwBJ8AWgRsSsgcAPT2P0DX6ftt22m+exopMyHyGkA4hyQ+mlrQHxSSgvlC+e
e0XWKvvdkwnw
-----END CERTIFICATE-----"
readonly ROOT_CA_CERT="-----BEGIN CERTIFICATE-----
MIIEDTCCAvWgAwIBAgICATgwDQYJKoZIhvcNAQELBQAwgZ4xJTAjBgkqhkiG9w0B
CQEMFmNlcnRhZG1pbkBuZXRza29wZS5jb20xGzAZBgNVBAMMEiouc2luMi5nb3Nr
b3BlLmNvbTESMBAGA1UECwwJY2VydGFkbWluMRYwFAYDVQQKDA1OZXRza29wZSBJ
bmMuMRIwEAYDVQQHDAlTaW5nYXBvcmUxCzAJBgNVBAgMAlNHMQswCQYDVQQGDAJT
RzAeFw0yMjA4MjYxMTExMjhaFw0zMjA4MjMxMTExMjhaMIGeMSUwIwYJKoZIhvcN
AQkBDBZjZXJ0YWRtaW5AbmV0c2tvcGUuY29tMRswGQYDVQQDDBIqLnNpbjIuZ29z
a29wZS5jb20xEjAQBgNVBAsMCWNlcnRhZG1pbjEWMBQGA1UECgwNTmV0c2tvcGUg
SW5jLjESMBAGA1UEBwwJU2luZ2Fwb3JlMQswCQYDVQQIDAJTRzELMAkGA1UEBgwC
U0cwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCoHoeq8Je8uOUlNhLy
sXSzZouTR4CERbydCJPr3BIz9POnWG+Ee67dAgUYaIKVPSqYVqY8LLs6g45tAELm
oVgMnX8FbrHD29PuYYm0yqIM76eRFgIJbFjN+5ycoustHaa2J9ModL+csTyt33Y/
5Uzdad7/YHwnVhxa2fYLmrGvxaYJJ6j4WH9k0TCZufLAyY69PWPqgI4H9gfLgBV1
pbNS3YFqZvww+3mZIrttwoyXTwTFtWMtiwOrZ2Ila90/6zZ5GBeR0syLQ63sG0TK
9AbmhZ0dAX3Wk8/fFluqxZS6uxlETHLXZ4o8Bp9SSEXXXPKrRBW82JWmXTEDw2LV
N0KtAgMBAAGjUzBRMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFKHpWcD/voOM
AAy5jQJyB0Jg0DAYMB8GA1UdIwQYMBaAFKHpWcD/voOMAAy5jQJyB0Jg0DAYMA0G
CSqGSIb3DQEBCwUAA4IBAQCBZ3yhZyDLeKM3sBctx3k4ddwab0GFWo2vrd1Ds5A2
tWWGOo7f7MwISXYO701ruyjIP8ZiEY+lc8I9de3FYLGUzYGCUn7QWuOD/RjKTsOg
kj1LhMoPWg8hs81MPY6mK1FC19euidtwZAHXV4BLkECx5pJG1cqyVf5AIu1XlgDm
9NYAP1MZDFVsvnF6EVGcbWMl2zxkTXRgJhmCWAnsPT520Uvvnff813YzfafDGzT4
Fz3FwfJAc/+IfY+RQiVezKsk8WRRI1AEQmsRWDl6YA/pGeGvtFDQZ8dx1TACxWhW
zSCSMuE3eKl2CWZJfwJBb5Vly5ULnRqXaB/lkAHvwvgA
-----END CERTIFICATE-----"

# Color codes for enhanced output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly NC='\033[0m' # No Color

# Unicode symbols for better visual feedback
readonly CHECK_MARK="✅"
readonly CROSS_MARK="❌"
readonly WARNING_SIGN="⚠️"
readonly INFO_SIGN="ℹ"
readonly ROCKET="🚀"
readonly GEAR="⚙️"
readonly MAGNIFY="🔍"
readonly CLEAN="🧹"

# No dedicated temporary working directory; use atomic writes next to targets
# Minimal cleanup trap
trap 'exit 1' INT TERM

# Function: show_banner
# Description: Shows a colorful banner at script start
function show_banner() {
    echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║                    ${WHITE}NETSKOPE CA MANAGER${BLUE}                       ║${NC}"
    echo -e "${BOLD}${BLUE}║              ${CYAN}SSL Certificate Bundle Management${BLUE}               ║${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Function: print_section_header
# Description: Print a colorful section header
# Arguments:
#   $1 - Section title
#   $2 - Icon (optional)
function print_section_header() {
    local title="$1"
    local icon="${2:-$GEAR}"
    echo ""
    echo -e "${BOLD}${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${WHITE}  $icon  $title${NC}"
    echo -e "${BOLD}${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Function: clean_netskope_dir_keep_bundle
# Description: Cleans the .netskope directory and keeps only the bundle
function clean_netskope_dir_keep_bundle() {
    if [ -d "$HOME_CACERT_DIR" ]; then
        find "$HOME_CACERT_DIR" -mindepth 1 -maxdepth 1 -type f ! -name "$(basename "$HOME_CACERT_FILE")" -print0 2>/dev/null | xargs -0 rm -f 2>/dev/null || true
    fi
}

## Lightweight spinner helpers are not used elsewhere; removing for simplicity

# Verbosity control (0 = concise default; 1 = verbose)
VERBOSE=0

# Function: progress_bar
# Description: Shows a simple progress bar
# Arguments:
#   $1 - Current progress (0-100)
#   $2 - Message
function progress_bar() {
    local progress=$1
    local message="$2"
    local always_show="${3:-0}"
    local current="${4:-}"
    local total="${5:-}"
    if [ "${VERBOSE:-0}" -eq 0 ] && [ "$always_show" -ne 1 ]; then
        return 0
    fi
    # Clamp progress
    if [ "$progress" -lt 0 ]; then progress=0; fi
    if [ "$progress" -gt 100 ]; then progress=100; fi
    local width=50
    local filled=$((progress * width / 100))
    local empty=$((width - filled))
    local label="$message"
    if [ -n "$current" ] && [ -n "$total" ]; then
        label="$label ($current/$total)"
    fi
    printf "\r${BOLD}%s${NC} [" "$label"
    printf "%*s" $filled "" | tr ' ' '█'
    printf "%*s" $empty ""
    printf "] ${BOLD}%d%%${NC}" $progress
}

# Function: log_message
# Description: Enhanced logging with colors and icons
# Arguments:
#   $1 - Log level (INFO, ERROR, WARNING, SUCCESS, DEBUG)
#   $2 - Message to log
function log_message() {
    local level="$1"
    local message="$2"
    local timestamp="[$(date '+%Y-%m-%d %H:%M:%S')]"
    local color=""
    local icon=""
    # Suppress noisy INFO messages unless verbose
    if [ "$level" = "INFO" ] && [ "${VERBOSE:-0}" -eq 0 ]; then
        return 0
    fi
    
    case "$level" in
        "INFO")
            color="${BLUE}"
            icon="${INFO_SIGN}"
            ;;
        "SUCCESS")
            color="${GREEN}"
            icon="${CHECK_MARK}"
            ;;
        "ERROR")
            color="${RED}"
            icon="${CROSS_MARK}"
            ;;
        "WARNING")
            color="${YELLOW}"
            icon="${WARNING_SIGN}"
            ;;
        "DEBUG")
            color="${DIM}"
            icon="🐛"
            ;;
        *)
            color="${WHITE}"
            icon="${INFO_SIGN}"
            ;;
    esac
    
    # Console output with colors
    echo -e "${DIM}${timestamp}${NC} ${color}${icon} ${message}${NC}"
}

# Check for help option first (doesn't require sudo)
if [[ "$*" == *"--help"* ]] || [[ "$*" == *"-h"* ]]; then
    show_usage() {
        show_banner
        echo -e "${BOLD}${GREEN}USAGE:${NC}"
        echo -e "  ${CYAN}curl -fsSL <endpoint> | sudo bash -s -- [OPTIONS]${NC}"
        echo -e "  ${CYAN}$0 [OPTIONS]${NC}"
        echo ""
        echo -e "${BOLD}${GREEN}OPTIONS:${NC}"
        echo -e "  ${YELLOW}-h, --help${NC}              Show this help message"
        echo -e "  ${YELLOW}-r, --revert${NC}           Revert Netskope certificates and clean up configuration"
        echo ""
        echo -e "${BOLD}${GREEN}DESCRIPTION:${NC}"
        echo -e "  This script manages Netskope CA certificates and creates a combined"
        echo -e "  CA bundle that includes system certificates and Netskope certificates."
        echo -e "  Certificates are embedded in the script; no network access required."
        echo -e "  Environment variables are automatically configured in your shell."
        echo ""
        echo -e "${BOLD}${GREEN}EXAMPLES:${NC}"
        echo -e "  ${DIM}curl -fsSL <endpoint> | sudo bash -s --${NC}"
        echo -e "  ${DIM}curl -fsSL <endpoint> | sudo bash -s -- --revert${NC}"
        echo ""
    }
    show_usage
    exit 0
fi

# Check if script is running with sudo privileges
if [ "$EUID" -ne 0 ]; then
    show_banner
    echo -e "${RED}${CROSS_MARK} Error: This script must be run with sudo privileges${NC}"
    echo -e "${YELLOW}Usage: curl -fsSL <endpoint> | sudo bash -s -- [options]${NC}"
    exit 1
fi

# Show banner at start
show_banner

# Constants
readonly HOME_CACERT_DIR="$HOME/.netskope"
readonly HOME_CACERT_FILE="$HOME_CACERT_DIR/ca-bundle.pem"
readonly COMBINED_CERT_FILE="$HOME_CACERT_FILE"

# No certificate URLs needed; certificates are embedded in this script

# Ensure home cacert directory exists
if ! mkdir -p "$HOME_CACERT_DIR"; then
    echo "Failed to create directory: $HOME_CACERT_DIR" >&2
    exit 1
fi

 

# Function: check_certificate_installation
# Description: Checks if a certificate is installed in the system keychain
# Arguments:
#   $1 - Certificate name to check
# Returns:
#   0 if found, 1 if not found
function check_certificate_installation() {
    local cert_name="$1"
    if sudo security find-certificate -a -c "$cert_name" /Library/Keychains/System.keychain &>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Function: check_certificate_trust
# Description: Checks the trust settings of a certificate
# Arguments:
#   $1 - Certificate name to check
function check_certificate_trust() {
    local cert_name="$1"
    log_message "INFO" "Checking trust settings for $cert_name"
    
    # Get the SHA-1 hash of the certificate
    local cert_hash
    cert_hash=$(sudo security find-certificate -a -c "$cert_name" /Library/Keychains/System.keychain | grep "SHA-1" | awk '{print $3}')
    
    if [ -n "$cert_hash" ]; then
        # NOTE: security trust-settings-show can hang or require user interaction, so we skip it here.
        log_message "INFO" "Certificate $cert_name (SHA-1: $cert_hash) is installed"
    else
        log_message "ERROR" "Certificate $cert_name not found in system keychain"
    fi
}

# Function: verify_certificate_chain
# Description: Verifies the certificate chain using OpenSSL
function verify_certificate_chain() {
    # Build chain on the fly from embedded content and verify against root
    local temp_chain
    temp_chain=$(mktemp "$HOME_CACERT_DIR/netskope-chain.XXXXXX") || true
    if [ -z "${temp_chain:-}" ]; then
        temp_chain="$HOME_CACERT_DIR/netskope-chain.$$.$(date +%s)"
        : > "$temp_chain" 2>/dev/null || { log_message "ERROR" "Failed to create temporary chain file"; return 1; }
    fi
    printf "%s\n" "$CA_CERT" > "$temp_chain" || { rm -f "$temp_chain"; log_message "ERROR" "Failed to write intermediate certificate"; return 1; }
    printf "%s\n" "$ROOT_CA_CERT" >> "$temp_chain" || { rm -f "$temp_chain"; log_message "ERROR" "Failed to append root certificate"; return 1; }

    local temp_root
    temp_root=$(mktemp "$HOME_CACERT_DIR/netskope-root.XXXXXX") || true
    if [ -z "${temp_root:-}" ]; then
        temp_root="$HOME_CACERT_DIR/netskope-root.$$.$(date +%s)"
        : > "$temp_root" 2>/dev/null || { rm -f "$temp_chain"; log_message "ERROR" "Failed to create temporary root file"; return 1; }
    fi
    printf "%s\n" "$ROOT_CA_CERT" > "$temp_root" || { rm -f "$temp_chain" "$temp_root"; log_message "ERROR" "Failed to write root certificate"; return 1; }

    log_message "INFO" "Verifying certificate chain..."
    openssl verify -CAfile "$temp_root" "$temp_chain" &>/dev/null
    local verify_status=$?
    rm -f "$temp_chain" "$temp_root" 2>/dev/null || true
    if [ $verify_status -eq 0 ]; then
        log_message "INFO" "Certificate chain verification successful"
        return 0
    else
        log_message "ERROR" "Certificate chain verification failed"
        return 1
    fi
}

# Function: extract_and_verify_trust
# Description: Extracts a certificate from the keychain and verifies its trust status
# Arguments:
#   $1 - Certificate name
function extract_and_verify_trust() {
    local cert_name="$1"
    local temp_cert
    temp_cert=$(mktemp "$HOME_CACERT_DIR/temp-cert.XXXXXX.pem")

    # Extract the certificate to a temporary file
    sudo security find-certificate -a -c "$cert_name" -p /Library/Keychains/System.keychain > "$temp_cert"
    if [ ! -s "$temp_cert" ]; then
        log_message "ERROR" "Failed to extract $cert_name from keychain."
        rm -f "$temp_cert"
        return 1
    fi

    # Verify trust status
    if sudo security verify-cert -c "$temp_cert" &>/dev/null; then
        log_message "INFO" "$cert_name is trusted by the system keychain."
    else
        log_message "ERROR" "$cert_name is NOT trusted by the system keychain."
    fi
    rm -f "$temp_cert"
}

# Function: find_certifi_paths
# Description: Finds all cacert.pem files in certifi site-packages directories with spinner
# Returns:
#   0 on success, 1 if no files found
function find_certifi_paths() {
    log_message "INFO" "Searching for certifi cacert.pem files..."
    
    # Start background search with spinner
    local temp_result_file
    temp_result_file=$(mktemp "$HOME_CACERT_DIR/find-results.XXXXXX")
    
    # Create background task for the find operation
    (
        sudo find /System/Volumes/Data/ -type f -name cacert.pem -path "*/site-packages/certifi/*" 2>/dev/null > "$temp_result_file"
    ) &
    
    local search_pid=$!
    
    # Show spinner while searching
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    tput civis 2>/dev/null || true
    
    while kill -0 $search_pid 2>/dev/null; do
        local char="${spin:$i:1}"
        printf "\r${CYAN}%s${NC} ${BOLD}${MAGNIFY} Scanning system for certifi bundles...${NC}" "$char"
        i=$(( (i+1) % ${#spin} ))
        sleep 0.15
    done
    
    # Clean up spinner
    tput cnorm 2>/dev/null || true
    printf "\r%*s\r" 50 ""
    
    # Wait for the find command to complete
    wait $search_pid
    
    # Read results
    local certifi_paths
    certifi_paths=$(cat "$temp_result_file")
    rm -f "$temp_result_file"
    
    if [ -n "$certifi_paths" ]; then
        local count
        count=$(echo "$certifi_paths" | wc -l | tr -d ' ')
        log_message "SUCCESS" "Found ${BOLD}$count${NC} certifi cacert.pem file(s)"
        
        # Only show individual paths if there are 5 or fewer, otherwise just show summary
        if [ "$count" -le 5 ]; then
            log_message "INFO" "Locations:"
            while IFS= read -r path; do
                log_message "INFO" "  ${CYAN}$path${NC}"
            done <<< "$certifi_paths"
        else
            # Show just a few examples for large lists
            local examples
            examples=$(echo "$certifi_paths" | head -3)
            log_message "INFO" "Sample locations:"
            while IFS= read -r path; do
                log_message "INFO" "  ${CYAN}$path${NC}"
            done <<< "$examples"
            log_message "INFO" "  ${DIM}... and $((count - 3)) more${NC}"
        fi
        
        # Store paths in a global variable for use by other functions
        CERTIFI_PATHS="$certifi_paths"
        return 0
    else
        log_message "WARNING" "No certifi cacert.pem files found"
        return 1
    fi
}

# Function: count_certificate_instances
# Description: Counts how many instances of a certificate exist in a bundle file
# Arguments:
#   $1 - Path to the bundle file (cacert.pem)
#   $2 - Path to the certificate file to check for
# Returns:
#   Prints the count to stdout
function count_certificate_instances() {
    local bundle_file="$1"
    local cert_file="$2"
    local count=0
    
    if [ ! -f "$bundle_file" ] || [ ! -f "$cert_file" ]; then
        echo "$count"
        return
    fi
    
    # Get the SHA256 fingerprint of the certificate we're looking for
    local cert_fingerprint
    cert_fingerprint=$(openssl x509 -in "$cert_file" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
    
    if [ -z "$cert_fingerprint" ]; then
        echo "$count"
        return
    fi
    
    # Use openssl to extract all certificates from the bundle and check their fingerprints
    local temp_dir
    temp_dir=$(mktemp -d "$HOME_CACERT_DIR/remove-cert.XXXXXX")
    
    # Extract individual certificates from the bundle using a simple approach
    local cert_num=0
    local in_cert=false
    local cert_content=""
    
    while IFS= read -r line; do
        if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
            in_cert=true
            cert_content="$line"
        elif [[ "$line" == "-----END CERTIFICATE-----" ]]; then
            cert_content="$cert_content"$'\n'"$line"
            # Write the certificate to a temp file and check its fingerprint
            local temp_cert="$temp_dir/cert_$cert_num.pem"
            echo "$cert_content" > "$temp_cert"
            
            local bundle_fingerprint
            bundle_fingerprint=$(openssl x509 -in "$temp_cert" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
            
            if [ "$cert_fingerprint" = "$bundle_fingerprint" ]; then
                count=$((count + 1))
            fi
            
            cert_num=$((cert_num + 1))
            in_cert=false
            cert_content=""
        elif [ "$in_cert" = true ]; then
            cert_content="$cert_content"$'\n'"$line"
        fi
    done < "$bundle_file"
    
    rm -rf "$temp_dir"
    echo "$count"
}

# Function: check_certificate_in_bundle
# Description: Checks if a certificate exists in a bundle file by comparing fingerprints
# Arguments:
#   $1 - Path to the bundle file (cacert.pem)
#   $2 - Path to the certificate file to check for
# Returns:
#   0 if certificate exists in bundle, 1 if not found
function check_certificate_in_bundle() {
    local bundle_file="$1"
    local cert_file="$2"
    
    local count
    count=$(count_certificate_instances "$bundle_file" "$cert_file")
    
    if [ "$count" -gt 0 ]; then
        return 0
    else
        return 1
    fi
}

# Function: remove_certificate_from_bundle
# Description: Removes all instances of a certificate from a bundle file
# Arguments:
#   $1 - Path to the bundle file (cacert.pem)
#   $2 - Path to the certificate file to remove
#   $3 - Certificate name for logging
#   $4 - Optional "quiet" mode to suppress logging
# Returns:
#   0 on success, 1 on failure
function remove_certificate_from_bundle() {
    local bundle_file="$1"
    local cert_file="$2"
    local cert_name="$3"
    local quiet_mode="${4:-}"
    
    if [ ! -f "$bundle_file" ] || [ ! -f "$cert_file" ]; then
        log_message "ERROR" "Bundle file or certificate file not found"
        return 1
    fi
    
    # Get the SHA256 fingerprint of the certificate we want to remove
    local cert_fingerprint
    cert_fingerprint=$(openssl x509 -in "$cert_file" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
    
    if [ -z "$cert_fingerprint" ]; then
        log_message "ERROR" "Could not get fingerprint for $cert_name"
        return 1
    fi
    
    # Create a temporary file for the new bundle
    local temp_bundle
    temp_bundle=$(mktemp "$HOME_CACERT_DIR/filtered-bundle.XXXXXX")
    local temp_dir
    temp_dir=$(mktemp -d "$HOME_CACERT_DIR/count-cert.XXXXXX")
    
    # Parse the bundle and exclude matching certificates
    local cert_num=0
    local in_cert=false
    local cert_content=""
    local removed_count=0
    
    while IFS= read -r line; do
        if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
            in_cert=true
            cert_content="$line"
        elif [[ "$line" == "-----END CERTIFICATE-----" ]]; then
            cert_content="$cert_content"$'\n'"$line"
            
            # Write the certificate to a temp file and check its fingerprint
            local temp_cert="$temp_dir/cert_$cert_num.pem"
            echo "$cert_content" > "$temp_cert"
            
            local bundle_fingerprint
            bundle_fingerprint=$(openssl x509 -in "$temp_cert" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
            
            # Only add to new bundle if fingerprints don't match
            if [ "$cert_fingerprint" != "$bundle_fingerprint" ]; then
                echo "$cert_content" >> "$temp_bundle"
            else
                removed_count=$((removed_count + 1))
            fi
            
            cert_num=$((cert_num + 1))
            in_cert=false
            cert_content=""
        elif [ "$in_cert" = true ]; then
            cert_content="$cert_content"$'\n'"$line"
        fi
    done < "$bundle_file"
    
    # Replace the original bundle with the filtered one
    if sudo cp "$temp_bundle" "$bundle_file"; then
        if [ "$quiet_mode" != "quiet" ]; then
            log_message "INFO" "Removed $removed_count instance(s) of $cert_name from $bundle_file"
        fi
        rm -f "$temp_bundle"
        rm -rf "$temp_dir"
        return 0
    else
        if [ "$quiet_mode" != "quiet" ]; then
            log_message "ERROR" "Failed to update $bundle_file"
        fi
        rm -f "$temp_bundle"
        rm -rf "$temp_dir"
        return 1
    fi
}

# Function: ensure_single_certificate_instance
# Description: Ensures exactly one instance of a certificate exists in a bundle (quiet mode)
# Arguments:
#   $1 - Path to the bundle file (cacert.pem)
#   $2 - Path to the certificate file
#   $3 - Certificate name for logging
# Returns:
#   0 on success, 1 on failure
function ensure_single_certificate_instance() {
    local bundle_file="$1"
    local cert_file="$2"
    local cert_name="$3"
    
    if [ ! -f "$bundle_file" ] || [ ! -f "$cert_file" ]; then
        return 1
    fi
    
    # Count existing instances
    local count
    count=$(count_certificate_instances "$bundle_file" "$cert_file")
    
    if [ "$count" -eq 0 ]; then
        # No instances found, add one
        append_certificate_to_bundle "$bundle_file" "$cert_file" "$cert_name" "quiet"
    elif [ "$count" -eq 1 ]; then
        # Exactly one instance, perfect
        return 0
    else
        # Multiple instances found, remove all and add one
        # Remove all instances quietly
        if remove_certificate_from_bundle "$bundle_file" "$cert_file" "$cert_name" "quiet"; then
            # Add exactly one instance
            if sudo sh -c "echo '' >> '$bundle_file' && cat '$cert_file' >> '$bundle_file'" 2>/dev/null; then
                return 0
            else
                return 1
            fi
        else
            return 1
        fi
    fi
}

# Function: append_certificate_to_bundle
# Description: Appends a certificate to a bundle file if it doesn't already exist
# Arguments:
#   $1 - Path to the bundle file (cacert.pem)
#   $2 - Path to the certificate file to append
#   $3 - Certificate name for logging
#   $4 - Optional "quiet" mode to suppress logging
function append_certificate_to_bundle() {
    local bundle_file="$1"
    local cert_file="$2"
    local cert_name="$3"
    local quiet_mode="${4:-}"
    
    if [ ! -f "$bundle_file" ] || [ ! -f "$cert_file" ]; then
        log_message "ERROR" "Bundle file or certificate file not found"
        return 1
    fi
    
    # Check if certificate already exists
    if check_certificate_in_bundle "$bundle_file" "$cert_file"; then
        if [ "$quiet_mode" != "quiet" ]; then
            log_message "INFO" "$cert_name already exists in $bundle_file"
        fi
        return 0
    fi
    
    # Append certificate to bundle
    if sudo sh -c "echo '' >> '$bundle_file' && cat '$cert_file' >> '$bundle_file'" 2>/dev/null; then
        if [ "$quiet_mode" != "quiet" ]; then
            log_message "INFO" "Successfully added $cert_name to $bundle_file"
        fi
        return 0
    else
        if [ "$quiet_mode" != "quiet" ]; then
            log_message "ERROR" "Failed to add $cert_name to $bundle_file"
        fi
        return 1
    fi
}

# Function: find_system_ca_certificates
# Description: Finds all available system CA certificate sources on macOS
# Returns:
#   Array of certificate file paths
function find_system_ca_certificates() {
    local cert_sources=()
    
    log_message "INFO" "Searching for system CA certificate sources..."
    
    # Check Homebrew OpenSSL certificate bundle
    if [ -f "/opt/homebrew/etc/ca-certificates/cert.pem" ]; then
        cert_sources+=("/opt/homebrew/etc/ca-certificates/cert.pem")
        log_message "INFO" "Found Homebrew CA bundle: /opt/homebrew/etc/ca-certificates/cert.pem"
    fi
    
    # Check system SSL template certificate bundle
    if [ -f "/System/Library/Templates/Data/private/etc/ssl/cert.pem" ]; then
        cert_sources+=("/System/Library/Templates/Data/private/etc/ssl/cert.pem")
        log_message "INFO" "Found system SSL template bundle: /System/Library/Templates/Data/private/etc/ssl/cert.pem"
    fi
    
    # Check Intel Mac Homebrew path
    if [ -f "/usr/local/etc/ca-certificates/cert.pem" ]; then
        cert_sources+=("/usr/local/etc/ca-certificates/cert.pem")
        log_message "INFO" "Found Intel Mac Homebrew CA bundle: /usr/local/etc/ca-certificates/cert.pem"
    fi
    
    # Check for curl-ca-bundle (if installed via Homebrew)
    if [ -f "/opt/homebrew/share/ca-certificates/cacert.pem" ]; then
        cert_sources+=("/opt/homebrew/share/ca-certificates/cacert.pem")
        log_message "INFO" "Found curl CA bundle: /opt/homebrew/share/ca-certificates/cacert.pem"
    fi
    
    # Store in global variable
    SYSTEM_CA_SOURCES=("${cert_sources[@]}")
    
    if [ ${#cert_sources[@]} -eq 0 ]; then
        log_message "WARNING" "No system CA certificate sources found"
        return 1
    else
        log_message "SUCCESS" "Found ${BOLD}${#cert_sources[@]}${NC} system CA certificate source(s)"
        return 0
    fi
}

# Function: extract_certificates_from_keychain
# Description: Extracts trusted root certificates from macOS system keychain
# Arguments:
#   $1 - Output file path
# Returns:
#   0 on success, 1 on failure
function extract_certificates_from_keychain() {
    local output_file="$1"
    local temp_dir
    temp_dir=$(mktemp -d "$HOME_CACERT_DIR/validate-bundle.XXXXXX")
    
    log_message "INFO" "Extracting certificates from macOS system keychain..."
    
    # Get list of all certificates in system keychain
    local cert_count=0
    
    # Export all system root certificates
    if sudo security export -t certs -f pemseq -k /System/Library/Keychains/SystemRootCertificates.keychain -o "${temp_dir}/system_roots.pem" &>/dev/null; then
        if [ -f "${temp_dir}/system_roots.pem" ] && [ -s "${temp_dir}/system_roots.pem" ]; then
            cat "${temp_dir}/system_roots.pem" >> "$output_file"
            cert_count=$(grep -c "BEGIN CERTIFICATE" "${temp_dir}/system_roots.pem" 2>/dev/null || echo 0)
            log_message "INFO" "Extracted $cert_count certificates from SystemRootCertificates keychain"
        fi
    fi
    
    # Also try to export from System keychain
    if sudo security export -t certs -f pemseq -k /Library/Keychains/System.keychain -o "${temp_dir}/system_certs.pem" &>/dev/null; then
        if [ -f "${temp_dir}/system_certs.pem" ] && [ -s "${temp_dir}/system_certs.pem" ]; then
            cat "${temp_dir}/system_certs.pem" >> "$output_file"
            local additional_count
            additional_count=$(grep -c "BEGIN CERTIFICATE" "${temp_dir}/system_certs.pem" 2>/dev/null || echo 0)
            cert_count=$((cert_count + additional_count))
            log_message "INFO" "Extracted $additional_count additional certificates from System keychain"
        fi
    fi
    
    rm -rf "$temp_dir"
    
    if [ "$cert_count" -gt 0 ]; then
        log_message "INFO" "Successfully extracted $cert_count certificates from system keychains"
        return 0
    else
        log_message "WARNING" "No certificates extracted from system keychains"
        return 1
    fi
}

# Function: create_combined_ca_bundle
# Description: Creates a combined CA bundle with system certificates and Netskope certificates
# Returns:
#   0 on success, 1 on failure
function create_combined_ca_bundle() {
    local temp_bundle
    temp_bundle=$(mktemp "$HOME_CACERT_DIR/ca-bundle.XXXXXX")
    local cert_count=0
    
    log_message "INFO" "Creating combined CA certificate bundle..."
    
    # Ensure output directory exists
    if [ ! -d "$HOME_CACERT_DIR" ]; then
        if ! mkdir -p "$HOME_CACERT_DIR"; then
            log_message "ERROR" "Failed to create SSL certificate directory: $HOME_CACERT_DIR"
            return 1
        fi
    fi
    
    # Start with system CA certificates from available sources
    local added_sources=0
    for source in "${SYSTEM_CA_SOURCES[@]}"; do
        if [ -f "$source" ] && [ -s "$source" ]; then
            log_message "INFO" "Adding certificates from: $source"
            cat "$source" >> "$temp_bundle"
            local source_count
            source_count=$(grep -c "BEGIN CERTIFICATE" "$source" 2>/dev/null || echo 0)
            cert_count=$((cert_count + source_count))
            added_sources=$((added_sources + 1))
            
            # Add a blank line between sources for clarity
            echo "" >> "$temp_bundle"
        fi
    done
    
    # If no system sources were found, try extracting from keychain
    if [ "$added_sources" -eq 0 ]; then
        log_message "INFO" "No system CA bundles found, attempting to extract from keychain..."
        extract_certificates_from_keychain "$temp_bundle"
        cert_count=$(grep -c "BEGIN CERTIFICATE" "$temp_bundle" 2>/dev/null || echo 0)
    fi
    
    # Add Netskope certificates from embedded variables
    log_message "INFO" "Adding Netskope root CA certificate"
    echo "" >> "$temp_bundle"
    echo "# Netskope Root CA Certificate" >> "$temp_bundle"
    printf "%s\n" "$ROOT_CA_CERT" >> "$temp_bundle"
    cert_count=$((cert_count + 1))

    log_message "INFO" "Adding Netskope intermediate CA certificate"
    echo "" >> "$temp_bundle"
    echo "# Netskope Intermediate CA Certificate" >> "$temp_bundle"
    printf "%s\n" "$CA_CERT" >> "$temp_bundle"
    cert_count=$((cert_count + 1))
    
    # Remove existing bundle if it exists (no backup)
    if [ -f "$COMBINED_CERT_FILE" ]; then
        log_message "INFO" "Overwriting existing bundle: $COMBINED_CERT_FILE"
    fi
    
    # Move temporary bundle to final location
    if mv "$temp_bundle" "$COMBINED_CERT_FILE"; then
        log_message "SUCCESS" "Successfully created combined CA bundle with $cert_count certificates"
        log_message "INFO" "Bundle location: ${CYAN}$COMBINED_CERT_FILE${NC}"
        
        # Set appropriate permissions
        chmod 644 "$COMBINED_CERT_FILE"
        
        return 0
    else
        log_message "ERROR" "Failed to create combined CA bundle"
        rm -f "$temp_bundle"
        return 1
    fi
}

# Function: copy_bundle_to_home
# Description: Copies the combined CA bundle to user's home directory
# Returns:
#   0 on success, 1 on failure
function copy_bundle_to_home() {
    log_message "INFO" "Copying CA bundle to home directory..."
    
    # Create .netskope directory if it doesn't exist
    if [ ! -d "$HOME_CACERT_DIR" ]; then
        if ! mkdir -p "$HOME_CACERT_DIR"; then
            log_message "ERROR" "Failed to create directory: $HOME_CACERT_DIR"
            return 1
        fi
        log_message "INFO" "Created directory: $HOME_CACERT_DIR"
    fi
    
    # Copy the bundle file
    if [ ! -f "$COMBINED_CERT_FILE" ]; then
        log_message "ERROR" "Source bundle file not found: $COMBINED_CERT_FILE"
        return 1
    fi
    
    # If source and destination are identical, just ensure permissions and return
    if [ "$COMBINED_CERT_FILE" = "$HOME_CACERT_FILE" ]; then
        chmod 644 "$HOME_CACERT_FILE" 2>/dev/null || true
        log_message "INFO" "Bundle already at destination: $HOME_CACERT_FILE"
        # Clean any extra files in the directory, keep only the bundle
        clean_netskope_dir_keep_bundle
        return 0
    fi

    # Copy the file
    if cp "$COMBINED_CERT_FILE" "$HOME_CACERT_FILE"; then
        chmod 644 "$HOME_CACERT_FILE"
        log_message "INFO" "Successfully copied CA bundle to: $HOME_CACERT_FILE"
        
        # Verify the copy
        local source_count target_count
        source_count=$(grep -c "BEGIN CERTIFICATE" "$COMBINED_CERT_FILE" 2>/dev/null || echo 0)
        target_count=$(grep -c "BEGIN CERTIFICATE" "$HOME_CACERT_FILE" 2>/dev/null || echo 0)
        
        if [ "$source_count" -eq "$target_count" ]; then
            log_message "INFO" "Bundle verification successful: $target_count certificates copied"
            # Clean any extra files in the directory, keep only the bundle
            clean_netskope_dir_keep_bundle
            return 0
        else
            log_message "ERROR" "Bundle verification failed: source=$source_count, target=$target_count"
            return 1
        fi
    else
        log_message "ERROR" "Failed to copy bundle to: $HOME_CACERT_FILE"
        return 1
    fi
}

# Function: configure_shell_environment
# Description: Automatically detects the user's shell and configures SSL environment variables
# Returns:
#   0 on success, 1 on failure
function configure_shell_environment() {
    log_message "INFO" "Automatically configuring SSL environment variables..."
    
    # Check if bundle exists
    if [ ! -f "$HOME_CACERT_FILE" ]; then
        log_message "ERROR" "CA bundle not found at $HOME_CACERT_FILE"
        return 1
    fi
    
    # Get the actual user (not root when using sudo)
    local actual_user="${SUDO_USER:-$USER}"
    local actual_home
    actual_home=$(eval echo "~$actual_user")
    
    # Detect the user's shell using multiple methods
    local user_shell=""
    local shell_name=""
    
    # Method 1: Check SUDO_USER's original SHELL environment (most reliable)
    if [ -n "${SUDO_USER:-}" ]; then
        # Get the original user's shell from their environment
        user_shell=$(sudo -u "$actual_user" bash -c 'echo $SHELL' 2>/dev/null)
        if [ -z "$user_shell" ]; then
            # Fallback: check what shell the user is actually running
            user_shell=$(sudo -u "$actual_user" ps -p $$ -o comm= 2>/dev/null | head -1)
        fi
    fi
    
    # Method 2: Check /etc/passwd (fallback)
    if [ -z "$user_shell" ]; then
        if command -v getent >/dev/null 2>&1; then
            user_shell=$(getent passwd "$actual_user" 2>/dev/null | cut -d: -f7)
        else
            # macOS doesn't always have getent, use dscl instead
            user_shell=$(dscl . -read "/Users/$actual_user" UserShell 2>/dev/null | awk '{print $2}')
        fi
    fi
    
    # Method 3: Check common shell locations (last resort)
    if [ -z "$user_shell" ] || [ ! -x "$user_shell" ]; then
        log_message "WARNING" "Could not reliably detect user shell, checking common locations..."
        for shell in "/bin/zsh" "/usr/local/bin/zsh" "/opt/homebrew/bin/zsh" "/bin/bash" "/usr/local/bin/bash"; do
            if [ -x "$shell" ]; then
                # Check if this shell is commonly used
                if [ "$shell" = "/bin/zsh" ] && [ -f "$actual_home/.zshrc" ]; then
                    user_shell="$shell"
                    break
                elif [ "$shell" = "/bin/bash" ] && ([ -f "$actual_home/.bash_profile" ] || [ -f "$actual_home/.bashrc" ]); then
                    user_shell="$shell"
                    break
                fi
            fi
        done
    fi
    
    # Extract shell name
    if [ -n "$user_shell" ]; then
        shell_name=$(basename "$user_shell")
    else
        log_message "WARNING" "Could not detect shell, defaulting to bash"
        shell_name="bash"
        user_shell="/bin/bash"
    fi
    
    log_message "INFO" "Detected user shell: $user_shell ($shell_name)"
    
    local shell_profile=""
    local env_vars_block=""
    
    # Prepare environment variables block
    local cert_count
    cert_count=$(grep -c "BEGIN CERTIFICATE" "$HOME_CACERT_FILE" 2>/dev/null || echo 0)
    
    # Determine appropriate shell profile and environment variable syntax
    case "$shell_name" in
        "bash")
            # macOS bash prefers .bash_profile, Linux prefers .bashrc
            if [ -f "$actual_home/.bash_profile" ]; then
                shell_profile="$actual_home/.bash_profile"
            elif [ -f "$actual_home/.bashrc" ]; then
                shell_profile="$actual_home/.bashrc"
            else
                # Create .bash_profile on macOS (default for login shells)
                shell_profile="$actual_home/.bash_profile"
            fi
            env_vars_block="
# Netskope SSL Certificate Configuration (added by mac-os.sh)
export SSL_CERT_FILE=\"$HOME_CACERT_FILE\"
export NODE_EXTRA_CA_CERTS=\"$HOME_CACERT_FILE\"
export REQUESTS_CA_BUNDLE=\"$HOME_CACERT_FILE\"
export GIT_SSL_CAINFO=\"$HOME_CACERT_FILE\"
export AWS_CA_BUNDLE=\"$HOME_CACERT_FILE\"
export DENO_CERT=\"$HOME_CACERT_FILE\"
# End Netskope SSL Configuration"
            ;;
        "zsh")
            shell_profile="$actual_home/.zshrc"
            env_vars_block="
# Netskope SSL Certificate Configuration (added by mac-os.sh)
export SSL_CERT_FILE=\"$HOME_CACERT_FILE\"
export NODE_EXTRA_CA_CERTS=\"$HOME_CACERT_FILE\"
export REQUESTS_CA_BUNDLE=\"$HOME_CACERT_FILE\"
export GIT_SSL_CAINFO=\"$HOME_CACERT_FILE\"
export AWS_CA_BUNDLE=\"$HOME_CACERT_FILE\"
export DENO_CERT=\"$HOME_CACERT_FILE\"
# End Netskope SSL Configuration"
            ;;
        "fish")
            shell_profile="$actual_home/.config/fish/config.fish"
            # Create fish config directory if it doesn't exist
            if [ ! -d "$actual_home/.config/fish" ]; then
                if ! sudo -u "$actual_user" mkdir -p "$actual_home/.config/fish" 2>/dev/null; then
                    log_message "ERROR" "Failed to create fish config directory"
                    return 1
                fi
            fi
            env_vars_block="
# Netskope SSL Certificate Configuration (added by mac-os.sh)
set -gx SSL_CERT_FILE \"$HOME_CACERT_FILE\"
set -gx NODE_EXTRA_CA_CERTS \"$HOME_CACERT_FILE\"
set -gx REQUESTS_CA_BUNDLE \"$HOME_CACERT_FILE\"
set -gx GIT_SSL_CAINFO \"$HOME_CACERT_FILE\"
set -gx AWS_CA_BUNDLE \"$HOME_CACERT_FILE\"
set -gx DENO_CERT \"$HOME_CACERT_FILE\"
# End Netskope SSL Configuration"
            ;;
        "tcsh"|"csh")
            shell_profile="$actual_home/.cshrc"
            env_vars_block="
# Netskope SSL Certificate Configuration (added by mac-os.sh)
setenv SSL_CERT_FILE \"$HOME_CACERT_FILE\"
setenv NODE_EXTRA_CA_CERTS \"$HOME_CACERT_FILE\"
setenv REQUESTS_CA_BUNDLE \"$HOME_CACERT_FILE\"
setenv GIT_SSL_CAINFO \"$HOME_CACERT_FILE\"
setenv AWS_CA_BUNDLE \"$HOME_CACERT_FILE\"
setenv DENO_CERT \"$HOME_CACERT_FILE\"
# End Netskope SSL Configuration"
            ;;
        *)
            # Fallback: try to find existing profile files, or use .profile
            local profile_candidates=("$actual_home/.profile" "$actual_home/.bash_profile" "$actual_home/.bashrc" "$actual_home/.zshrc")
            shell_profile=""
            
            for candidate in "${profile_candidates[@]}"; do
                if [ -f "$candidate" ]; then
                    shell_profile="$candidate"
                    log_message "INFO" "Using existing profile file: $candidate"
                    break
                fi
            done
            
            # If no existing profile found, default to .profile
            if [ -z "$shell_profile" ]; then
                shell_profile="$actual_home/.profile"
                log_message "INFO" "No existing profile found, will create: $shell_profile"
            fi
            
            env_vars_block="
# Netskope SSL Certificate Configuration (added by mac-os.sh)
export SSL_CERT_FILE=\"$HOME_CACERT_FILE\"
export NODE_EXTRA_CA_CERTS=\"$HOME_CACERT_FILE\"
export REQUESTS_CA_BUNDLE=\"$HOME_CACERT_FILE\"
export GIT_SSL_CAINFO=\"$HOME_CACERT_FILE\"
export AWS_CA_BUNDLE=\"$HOME_CACERT_FILE\"
export DENO_CERT=\"$HOME_CACERT_FILE\"
# End Netskope SSL Configuration"
            ;;
    esac
    
    log_message "INFO" "Detected shell: $shell_name"
    log_message "INFO" "Target profile: $shell_profile"
    
    # Validate that we can write to the target directory
    local profile_dir
    profile_dir=$(dirname "$shell_profile")
    if [ ! -d "$profile_dir" ]; then
        log_message "INFO" "Creating profile directory: $profile_dir"
        if ! sudo -u "$actual_user" mkdir -p "$profile_dir" 2>/dev/null; then
            log_message "ERROR" "Failed to create profile directory: $profile_dir"
            return 1
        fi
    fi
    
    # Always clean up any existing Netskope SSL environment variables for idempotency
    log_message "INFO" "Cleaning up any existing Netskope SSL environment variables..."
    
    if [ -f "$shell_profile" ]; then
        local temp_profile
        temp_profile=$(mktemp)
        local cleanup_made=false
        
        # Create a comprehensive cleanup that removes:
        # 1. Configuration blocks (between markers)
        # 2. Individual environment variable lines that might exist outside blocks
        # 3. Any legacy configurations
        
        # List of environment variables to clean up
        local env_vars=(
            "SSL_CERT_FILE"
            "NODE_EXTRA_CA_CERTS"
            "REQUESTS_CA_BUNDLE"
            "GIT_SSL_CAINFO"
            "AWS_CA_BUNDLE"
            "DENO_CERT"
        )
        
        # First, remove configuration blocks (between markers)
        awk '
            /# Netskope SSL Certificate Configuration/ { skip = 1; next }
            /# End Netskope SSL Configuration/ { skip = 0; next }
            !skip { print }
        ' "$shell_profile" > "$temp_profile" 2>/dev/null
        
        # Then, remove any individual environment variable lines that reference our cert file
        # or any Netskope-related paths
        local cert_path_pattern="$HOME_CACERT_FILE"
        cert_path_pattern="${cert_path_pattern//\//\\/}"  # Escape forward slashes for sed
        
        for var in "${env_vars[@]}"; do
            # Remove various patterns for each shell type
            case "$shell_name" in
                "fish")
                    # Remove fish-style variable declarations
                    sed -i.bak "/^[[:space:]]*set[[:space:]]\+-gx[[:space:]]\+${var}[[:space:]]*\"/d" "$temp_profile" 2>/dev/null || true
                    sed -i.bak "/^[[:space:]]*set[[:space:]]\+-gx[[:space:]]\+${var}[[:space:]]*=/d" "$temp_profile" 2>/dev/null || true
                    ;;
                "tcsh"|"csh")
                    # Remove csh-style variable declarations
                    sed -i.bak "/^[[:space:]]*setenv[[:space:]]\+${var}[[:space:]]/d" "$temp_profile" 2>/dev/null || true
                    ;;
                *)
                    # Remove bash/zsh/sh-style variable declarations
                    sed -i.bak "/^[[:space:]]*export[[:space:]]\+${var}[[:space:]]*=/d" "$temp_profile" 2>/dev/null || true
                    sed -i.bak "/^[[:space:]]*${var}[[:space:]]*=/d" "$temp_profile" 2>/dev/null || true
                    ;;
            esac
        done
        
        # Remove any backup files created by sed
        rm -f "${temp_profile}.bak" 2>/dev/null || true
        
        # Check if any cleanup was actually performed
        if [ -f "$temp_profile" ] && ! cmp -s "$shell_profile" "$temp_profile" 2>/dev/null; then
            cleanup_made=true
            log_message "INFO" "Found existing Netskope SSL configuration - cleaning up for idempotency"
            
            # Replace the original file
            if sudo -u "$actual_user" cp "$temp_profile" "$shell_profile" 2>/dev/null; then
                log_message "INFO" "Successfully cleaned up existing Netskope SSL environment variables"
            else
                # If user fails, try as root (handles files created by previous sudo runs)
                if cp "$temp_profile" "$shell_profile" 2>/dev/null; then
                    # Restore proper ownership after root write
                    if chown "$actual_user" "$shell_profile" 2>/dev/null; then
                        log_message "INFO" "Successfully cleaned up existing configuration (with ownership fix)"
                    else
                        log_message "WARNING" "Cleaned up configuration but could not restore ownership"
                    fi
                else
                    log_message "WARNING" "Could not clean up existing configuration, will append new one"
                fi
            fi
        else
            log_message "INFO" "No existing Netskope SSL configuration found - profile is clean"
        fi
        
        rm -f "$temp_profile"
    else
        log_message "INFO" "Shell profile does not exist yet - will create new one"
    fi
    
    # Add new configuration with better error handling
    log_message "INFO" "Adding SSL environment variables to $shell_profile"
    
    # Check if profile file exists and get its permissions
    if [ -f "$shell_profile" ]; then
        local file_perms
        file_perms=$(ls -la "$shell_profile" 2>/dev/null | awk '{print $1}')
        log_message "INFO" "Existing profile file permissions: $file_perms"
        
        # Check if the file is writable by the user
        if ! sudo -u "$actual_user" test -w "$shell_profile" 2>/dev/null; then
            log_message "WARNING" "Profile file is not writable by user, attempting to fix permissions"
            # Try to make it writable by the user
            if ! sudo chown "$actual_user" "$shell_profile" 2>/dev/null; then
                log_message "WARNING" "Could not change ownership of profile file"
            fi
            if ! sudo chmod u+w "$shell_profile" 2>/dev/null; then
                log_message "WARNING" "Could not make profile file writable"
            fi
        fi
    fi
    
    # Create a temporary file with the configuration
    local temp_config
    temp_config=$(mktemp)
    if ! echo "$env_vars_block" > "$temp_config" 2>/dev/null; then
        log_message "ERROR" "Failed to create temporary configuration file"
        rm -f "$temp_config"
        return 1
    fi
    
    # Try multiple methods to append the configuration
    local write_success=false
    local write_method=""
    
    # Method 1: Direct append as user
    if ! $write_success; then
        if sudo -u "$actual_user" cat "$temp_config" >> "$shell_profile" 2>/dev/null; then
            write_success=true
            write_method="direct append"
        fi
    fi
    
    # Method 2: Using tee as user
    if ! $write_success; then
        if sudo -u "$actual_user" tee -a "$shell_profile" < "$temp_config" >/dev/null 2>&1; then
            write_success=true
            write_method="tee append"
        fi
    fi
    
    # Method 3: Copy existing file, append, then replace
    if ! $write_success; then
        local temp_profile
        temp_profile=$(mktemp)
        if [ -f "$shell_profile" ]; then
            cat "$shell_profile" > "$temp_profile" 2>/dev/null
        fi
        if cat "$temp_config" >> "$temp_profile" 2>/dev/null; then
            if sudo -u "$actual_user" cp "$temp_profile" "$shell_profile" 2>/dev/null; then
                write_success=true
                write_method="copy and replace"
            fi
        fi
        rm -f "$temp_profile"
    fi
    
    # Method 4: Use bash -c with different quoting
    if ! $write_success; then
        local escaped_content
        escaped_content=$(printf '%s' "$env_vars_block" | sed 's/"/\\"/g')
        if sudo -u "$actual_user" bash -c "printf '%s' \"$escaped_content\" >> '$shell_profile'" 2>/dev/null; then
            write_success=true
            write_method="bash printf"
        fi
    fi
    
    # Clean up temp config file
    rm -f "$temp_config"
    
    if $write_success; then
        log_message "INFO" "Successfully wrote configuration using: $write_method"
        
        # Verify the configuration was added
        if grep -q "SSL_CERT_FILE.*$HOME_CACERT_FILE" "$shell_profile" 2>/dev/null; then
            log_message "SUCCESS" "Successfully configured SSL environment variables"
            log_message "INFO" "Shell profile: ${CYAN}$shell_profile${NC}"
            log_message "INFO" "Certificate bundle: ${CYAN}$HOME_CACERT_FILE${NC} (${BOLD}$cert_count${NC} certificates)"
            echo ""
            return 0
        else
            log_message "ERROR" "Configuration appears to have been written but verification failed"
            log_message "ERROR" "Please check $shell_profile manually"
            return 1
        fi
    else
        log_message "ERROR" "All methods to write SSL environment variables to $shell_profile failed"
        log_message "ERROR" "This may be due to file permissions, disk space, or system restrictions"
        log_message "ERROR" ""
        log_message "ERROR" "Please manually add the following to your shell profile ($shell_profile):"
        log_message "ERROR" ""
        while IFS= read -r line; do
            log_message "ERROR" "$line"
        done <<< "$env_vars_block"
        log_message "ERROR" ""
        log_message "ERROR" "Then run: source $shell_profile"
        return 1
    fi
}

# Function: validate_combined_bundle
# Description: Validates the combined certificate bundle
# Returns:
#   0 if valid, 1 if invalid
function validate_combined_bundle() {
    if [ ! -f "$COMBINED_CERT_FILE" ]; then
        log_message "ERROR" "Combined certificate bundle not found: $COMBINED_CERT_FILE"
        return 1
    fi
    
    log_message "INFO" "Validating combined certificate bundle..."
    
    # Count certificates in bundle
    local cert_count
    cert_count=$(grep -c "BEGIN CERTIFICATE" "$COMBINED_CERT_FILE" 2>/dev/null || echo 0)
    
    if [ "$cert_count" -eq 0 ]; then
        log_message "ERROR" "No certificates found in bundle"
        return 1
    fi
    
    log_message "INFO" "Bundle contains $cert_count certificates"
    
    # Test a few certificates for validity
    local temp_dir
    temp_dir=$(mktemp -d "$HOME_CACERT_DIR/remove-certifi.XXXXXX")
    local cert_num=0
    local valid_certs=0
    local invalid_certs=0
    
    # Extract and validate individual certificates (first 5 certificates only)
    awk -v tempdir="$temp_dir" '
        /-----BEGIN CERTIFICATE-----/ { 
            cert++; 
            if (cert <= 5) {
                filename = tempdir "/cert" cert ".pem"
                in_cert = 1
            }
        }
        cert <= 5 && in_cert { print > filename }
        /-----END CERTIFICATE-----/ { 
            if (cert <= 5) {
                close(filename)
                in_cert = 0
            }
            if (cert >= 5) exit
        }
    ' "$COMBINED_CERT_FILE"
    
    for cert_file in "$temp_dir"/cert*.pem; do
        if [ -f "$cert_file" ]; then
            cert_num=$((cert_num + 1))
            if openssl x509 -in "$cert_file" -noout -text &>/dev/null; then
                valid_certs=$((valid_certs + 1))
            else
                invalid_certs=$((invalid_certs + 1))
                log_message "WARNING" "Invalid certificate found (cert #$cert_num)"
            fi
        fi
    done
    
    rm -rf "$temp_dir"
    
    log_message "INFO" "Validation complete: $valid_certs valid, $invalid_certs invalid (from first 5 tested)"
    
    if [ "$valid_certs" -gt 0 ]; then
        log_message "INFO" "Combined certificate bundle is valid"
        return 0
    else
        log_message "ERROR" "Combined certificate bundle validation failed"
        return 1
    fi
}

# Function: update_certifi_bundles
# Description: Updates all found certifi cacert.pem files with missing Netskope certificates
function update_certifi_bundles() {
    local temp_dir
    temp_dir=$(mktemp -d "$HOME_CACERT_DIR/update-certifi.XXXXXX")
    local root_cert="$temp_dir/root.pem"
    local intermediate_cert="$temp_dir/intermediate.pem"
    printf "%s\n" "$ROOT_CA_CERT" > "$root_cert"
    printf "%s\n" "$CA_CERT" > "$intermediate_cert"
    
    if [ -z "${CERTIFI_PATHS:-}" ]; then
        log_message "INFO" "No certifi paths found to update"
        return 0
    fi
    
    local total_files
    total_files=$(echo "$CERTIFI_PATHS" | wc -l | tr -d ' ')
    log_message "INFO" "Updating ${BOLD}$total_files${NC} certifi bundle(s) with Netskope certificates..."
    
    local current=0
    local files_updated=0
    local files_modified=()
    
    while IFS= read -r cacert_path; do
        current=$((current + 1))
        
        # Show progress for every file processed; always visible with n/total
        progress_bar $((current * 100 / total_files)) "Updating application trust" 1 "$current" "$total_files"
        
        local file_was_modified=false
        
        # Check if root certificate needs to be added/fixed
        local root_count
        root_count=$(count_certificate_instances "$cacert_path" "$root_cert")
        if [ "$root_count" -ne 1 ]; then
            ensure_single_certificate_instance "$cacert_path" "$root_cert" "Netskope Root CA"
            file_was_modified=true
        fi
        
        # Check if intermediate certificate needs to be added/fixed
        local intermediate_count
        intermediate_count=$(count_certificate_instances "$cacert_path" "$intermediate_cert")
        if [ "$intermediate_count" -ne 1 ]; then
            ensure_single_certificate_instance "$cacert_path" "$intermediate_cert" "Netskope Intermediate CA"
            file_was_modified=true
        fi
        
        if [ "$file_was_modified" = true ]; then
            files_updated=$((files_updated + 1))
            files_modified+=("$cacert_path")
        fi
        
    done <<< "$CERTIFI_PATHS"
    
    # Clear progress bar
    printf "\r%*s\r" 80 ""
    
    # Summary
    if [ "$files_updated" -gt 0 ]; then
        log_message "SUCCESS" "Updated ${BOLD}$files_updated${NC} of ${BOLD}$total_files${NC} certifi bundle(s)"
        
        if [ ${#files_modified[@]} -gt 0 ] && [ ${#files_modified[@]} -le 5 ]; then
            log_message "INFO" "Modified files:"
            for file in "${files_modified[@]}"; do
                log_message "INFO" "  ${CYAN}$file${NC}"
            done
        fi
    else
        log_message "SUCCESS" "All ${BOLD}$total_files${NC} certifi bundle(s) already have correct Netskope certificates"
    fi
    
    log_message "SUCCESS" "Finished updating certifi bundles"
}

# Function: update_gradle_jbr_trust
# Description: Imports Netskope certificates into Android Studio's bundled JBR truststore if present
function update_gradle_jbr_trust() {
    local jbr_bin_dir="/Applications/Android Studio.app/Contents/jbr/Contents/Home/bin"
    local keytool_path="$jbr_bin_dir/keytool"
    local keystore_path="$jbr_bin_dir/../lib/security/cacerts"

    if [ ! -d "$jbr_bin_dir" ] || [ ! -x "$keytool_path" ] || [ ! -f "$keystore_path" ]; then
        log_message "INFO" "Android Studio JBR not found; skipping Gradle trust update"
        return 0
    fi

    log_message "INFO" "Updating Gradle/Android Studio trust store"

    # Prepare temporary cert files
    local temp_dir
    temp_dir=$(mktemp -d "$HOME_CACERT_DIR/gradle-trust.XXXXXX")
    local root_cert_file="$temp_dir/root.pem"
    local inter_cert_file="$temp_dir/intermediate.pem"
    printf "%s\n" "$ROOT_CA_CERT" > "$root_cert_file"
    printf "%s\n" "$CA_CERT" > "$inter_cert_file"

    # Expected fingerprints (normalized without colons)
    local root_fp expected_inter_fp
    root_fp=$(openssl x509 -in "$root_cert_file" -noout -fingerprint -sha256 2>/dev/null | awk -F= '{print $2}' | tr -d ':')
    expected_inter_fp=$(openssl x509 -in "$inter_cert_file" -noout -fingerprint -sha256 2>/dev/null | awk -F= '{print $2}' | tr -d ':')

    # Default Java cacerts password
    local storepass="changeit"

    # Find all aliases
    local aliases
    aliases=$(sudo "$keytool_path" -list -v -keystore "$keystore_path" -storepass "$storepass" 2>/dev/null | awk -F": " '/^Alias name: /{print $2}')

    # Collect matches for root and intermediate (with progress)
    local root_hits=""
    local inter_hits=""
    if [ -n "$aliases" ]; then
        local total_aliases
        total_aliases=$(printf "%s\n" "$aliases" | sed '/^$/d' | wc -l | tr -d ' ')
        local current_alias=0
        while IFS= read -r alias; do
            [ -z "$alias" ] && continue
            current_alias=$((current_alias + 1))
            progress_bar $((current_alias * 100 / (total_aliases==0?1:total_aliases))) "Scanning Java trust store" 1 "$current_alias" "$total_aliases"
            local exported="$temp_dir/export-$alias.pem"
            if sudo "$keytool_path" -exportcert -rfc -alias "$alias" -keystore "$keystore_path" -storepass "$storepass" -file "$exported" >/dev/null 2>&1; then
                local this_fp
                this_fp=$(openssl x509 -in "$exported" -noout -fingerprint -sha256 2>/dev/null | awk -F= '{print $2}' | tr -d ':')
                if [ -n "$this_fp" ]; then
                    if [ "$this_fp" = "$root_fp" ]; then
                        root_hits="$root_hits"$'\n'"$alias"
                    elif [ "$this_fp" = "$expected_inter_fp" ]; then
                        inter_hits="$inter_hits"$'\n'"$alias"
                    fi
                fi
            fi
        done <<EOF
$aliases
EOF
        # Clear progress line
        printf "\r%*s\r" 96 ""
    fi

    local alias_root="netskope-root"
    local alias_inter="netskope-intermediate"
    local root_action="" inter_action=""
    local root_dups_removed=0 inter_dups_removed=0

    # Ensure single root
    local root_count keep_root
    root_count=$(printf "%s" "$root_hits" | grep -c . 2>/dev/null || echo 0)
    if [ "$root_count" -eq 0 ]; then
        if sudo "$keytool_path" -importcert -trustcacerts -noprompt -keystore "$keystore_path" -storepass "$storepass" -alias "$alias_root" -file "$root_cert_file" >/dev/null 2>&1; then
            root_action="added"
        else
            root_action="failed"
        fi
    else
        keep_root=$(printf "%s" "$root_hits" | sed '/^$/d' | head -1)
        # Delete any extra duplicates beyond the first
        if [ "$root_count" -gt 1 ]; then
            root_dups_removed=$((root_count - 1))
            printf "%s" "$root_hits" | sed '/^$/d' | tail -n +2 | while IFS= read -r dup_alias; do
                sudo "$keytool_path" -delete -keystore "$keystore_path" -storepass "$storepass" -alias "$dup_alias" >/dev/null 2>&1 || true
            done
        fi
        root_action="already present"
    fi

    # Ensure single intermediate
    local inter_count keep_inter
    inter_count=$(printf "%s" "$inter_hits" | grep -c . 2>/dev/null || echo 0)
    if [ "$inter_count" -eq 0 ]; then
        if sudo "$keytool_path" -importcert -trustcacerts -noprompt -keystore "$keystore_path" -storepass "$storepass" -alias "$alias_inter" -file "$inter_cert_file" >/dev/null 2>&1; then
            inter_action="added"
        else
            inter_action="failed"
        fi
    else
        keep_inter=$(printf "%s" "$inter_hits" | sed '/^$/d' | head -1)
        if [ "$inter_count" -gt 1 ]; then
            inter_dups_removed=$((inter_count - 1))
            printf "%s" "$inter_hits" | sed '/^$/d' | tail -n +2 | while IFS= read -r dup_alias; do
                sudo "$keytool_path" -delete -keystore "$keystore_path" -storepass "$storepass" -alias "$dup_alias" >/dev/null 2>&1 || true
            done
        fi
        inter_action="already present"
    fi

    rm -rf "$temp_dir" 2>/dev/null || true

    # Concise summary (always visible)
    if [ "$root_action" = "failed" ] || [ "$inter_action" = "failed" ]; then
        log_message "WARNING" "Android Studio trust update encountered issues (root: $root_action, inter: $inter_action)"
    fi
    log_message "SUCCESS" "Android Studio trust: Root $root_action."
    log_message "SUCCESS" "Android Studio trust: Intermediate $inter_action."
}

# Function: remove_gradle_jbr_trust
# Description: Removes Netskope certificates from Android Studio's bundled JBR truststore if present
function remove_gradle_jbr_trust() {
    local jbr_bin_dir="/Applications/Android Studio.app/Contents/jbr/Contents/Home/bin"
    local keytool_path="$jbr_bin_dir/keytool"
    local keystore_path="$jbr_bin_dir/../lib/security/cacerts"

    if [ ! -d "$jbr_bin_dir" ] || [ ! -x "$keytool_path" ] || [ ! -f "$keystore_path" ]; then
        return 0
    fi

    local storepass="changeit"
    local alias_root="netskope-root"
    local alias_inter="netskope-intermediate"

    if sudo "$keytool_path" -list -keystore "$keystore_path" -storepass "$storepass" -alias "$alias_root" >/dev/null 2>&1; then
        sudo "$keytool_path" -delete -keystore "$keystore_path" -storepass "$storepass" -alias "$alias_root" >/dev/null 2>&1 || true
    fi
    if sudo "$keytool_path" -list -keystore "$keystore_path" -storepass "$storepass" -alias "$alias_inter" >/dev/null 2>&1; then
        sudo "$keytool_path" -delete -keystore "$keystore_path" -storepass "$storepass" -alias "$alias_inter" >/dev/null 2>&1 || true
    fi
}

# Function: fix_ownership_if_needed
# Description: Fixes file ownership if files were created by root during sudo operations
# Arguments:
#   $1 - File or directory path
#   $2 - Target user
function fix_ownership_if_needed() {
    local target_path="$1"
    local target_user="$2"
    
    if [ ! -e "$target_path" ]; then
        return 0
    fi
    
    # Check if the file/directory is owned by root but should be owned by user
    local current_owner
    current_owner=$(stat -f "%Su" "$target_path" 2>/dev/null || echo "unknown")
    
    if [ "$current_owner" = "root" ] && [ "$target_user" != "root" ]; then
        log_message "INFO" "Fixing ownership of $target_path (currently owned by $current_owner)"
        if chown -R "$target_user" "$target_path" 2>/dev/null; then
            log_message "INFO" "Successfully changed ownership to $target_user"
            return 0
        else
            log_message "WARNING" "Could not change ownership of $target_path"
            return 1
        fi
    fi
    
    return 0
}

# Function: remove_certificates_from_certifi
# Description: Removes Netskope certificates from all found certifi cacert.pem files (idempotent)
function remove_certificates_from_certifi() {
    local certificates_found=false
    local total_removed=0
    local files_with_certs=0
    local total_files=0
    
    local temp_dir
    temp_dir=$(mktemp -d "$HOME_CACERT_DIR/remove-certifi.XXXXXX")
    local root_cert="$temp_dir/root.pem"
    local intermediate_cert="$temp_dir/intermediate.pem"
    printf "%s\n" "$ROOT_CA_CERT" > "$root_cert"
    printf "%s\n" "$CA_CERT" > "$intermediate_cert"
    
    if [ -z "${CERTIFI_PATHS:-}" ]; then
        log_message "INFO" "No certifi paths found - skipping certifi bundle cleanup"
        return 0
    fi
    
    # Count total files first
    total_files=$(echo "$CERTIFI_PATHS" | wc -l | tr -d ' ')
    log_message "INFO" "Scanning ${BOLD}$total_files${NC} certifi bundle(s) for Netskope certificates..."
    
    # Show progress while checking files
    local current=0
    local files_modified=()
    
    while IFS= read -r cacert_path; do
        current=$((current + 1))
        
        if [ ! -f "$cacert_path" ]; then
            continue
        fi
        
        # Show progress for every file processed; always visible with n/total
        progress_bar $((current * 100 / total_files)) "Cleaning application trust" 1 "$current" "$total_files"
        
        local removed_from_this_file=0
        local this_file_had_certs=false
        
        # Check and remove root certificate instances
        local root_count
        root_count=$(count_certificate_instances "$cacert_path" "$root_cert")
        if [ "$root_count" -gt 0 ]; then
            if remove_certificate_from_bundle "$cacert_path" "$root_cert" "Netskope Root CA" "quiet"; then
                certificates_found=true
                this_file_had_certs=true
                removed_from_this_file=$((removed_from_this_file + root_count))
                total_removed=$((total_removed + root_count))
            fi
        fi
        
        # Check and remove intermediate certificate instances
        local intermediate_count
        intermediate_count=$(count_certificate_instances "$cacert_path" "$intermediate_cert")
        if [ "$intermediate_count" -gt 0 ]; then
            if remove_certificate_from_bundle "$cacert_path" "$intermediate_cert" "Netskope Intermediate CA" "quiet"; then
                certificates_found=true
                this_file_had_certs=true
                removed_from_this_file=$((removed_from_this_file + intermediate_count))
                total_removed=$((total_removed + intermediate_count))
            fi
        fi
        
        # Track files that actually had certificates (don't log yet)
        if [ "$this_file_had_certs" = true ]; then
            files_with_certs=$((files_with_certs + 1))
            files_modified+=("$cacert_path:$removed_from_this_file")
        fi
        
    done <<< "$CERTIFI_PATHS"
    
    # Clear progress bar
    printf "\r%*s\r" 80 ""
    
    # Summary
    if [ "$certificates_found" = true ]; then
        log_message "SUCCESS" "Successfully processed ${BOLD}$files_with_certs${NC} of ${BOLD}$total_files${NC} certifi bundle(s)"
        log_message "SUCCESS" "Removed ${BOLD}$total_removed${NC} Netskope certificate(s) total"
        
        if [ ${#files_modified[@]} -gt 0 ] && [ ${#files_modified[@]} -le 5 ]; then
            log_message "INFO" "Modified files:"
            for entry in "${files_modified[@]}"; do
                local file_path="${entry%:*}"
                local cert_count="${entry#*:}"
                log_message "INFO" "  ${CYAN}$file_path${NC} (${BOLD}$cert_count${NC} certs removed)"
            done
        elif [ ${#files_modified[@]} -gt 5 ]; then
            log_message "INFO" "Modified ${BOLD}${#files_modified[@]}${NC} files (too many to list individually)"
        fi
    else
        log_message "SUCCESS" "Scanned ${BOLD}$total_files${NC} certifi bundle(s) - all clean (no Netskope certificates found)"
    fi
}

# Function: remove_shell_environment
# Description: Removes Netskope SSL environment variables from shell profiles (idempotent)
# Returns:
#   0 on success, 1 on failure
function remove_shell_environment() {
    log_message "INFO" "Checking shell profiles for Netskope SSL environment variables..."
    
    # Get the actual user (not root when using sudo)
    local actual_user="${SUDO_USER:-$USER}"
    local actual_home
    actual_home=$(eval echo "~$actual_user")
    
    # List of potential shell profile files
    local profile_files=(
        "$actual_home/.bash_profile"
        "$actual_home/.bashrc"
        "$actual_home/.zshrc"
        "$actual_home/.profile"
        "$actual_home/.config/fish/config.fish"
        "$actual_home/.cshrc"
    )
    
    local removed_from_files=0
    local checked_files=0
    local existing_files=0
    
    for profile_file in "${profile_files[@]}"; do
        if [ -f "$profile_file" ]; then
            existing_files=$((existing_files + 1))
            checked_files=$((checked_files + 1))
            
            # Check if Netskope configuration exists
            if grep -q "Netskope SSL Certificate Configuration" "$profile_file" 2>/dev/null; then
                log_message "INFO" "Found Netskope SSL configuration in: $profile_file"
                
                # Create a temporary file
                local temp_profile
                temp_profile=$(mktemp)
                
                # Remove lines between the markers
                awk '
                    /# Netskope SSL Certificate Configuration/ { skip = 1; next }
                    /# End Netskope SSL Configuration/ { skip = 0; next }
                    !skip { print }
                ' "$profile_file" > "$temp_profile" 2>/dev/null
                
                # Verify the temp file was created successfully
                if [ -f "$temp_profile" ]; then
                    # Verify the content actually changed (idempotency check)
                    if ! cmp -s "$profile_file" "$temp_profile" 2>/dev/null; then
                        # Replace the original file - try user first, then root if needed
                        local update_success=false
                        
                        # Try as user first
                        if sudo -u "$actual_user" cp "$temp_profile" "$profile_file" 2>/dev/null; then
                            update_success=true
                        else
                            # If user fails, try as root (handles files created by previous sudo runs)
                            log_message "INFO" "User permission failed, trying as root for: $profile_file"
                            if cp "$temp_profile" "$profile_file" 2>/dev/null; then
                                # Restore proper ownership after root write
                                if chown "$actual_user" "$profile_file" 2>/dev/null; then
                                    log_message "INFO" "Restored ownership to user: $profile_file"
                                else
                                    log_message "WARNING" "Could not restore ownership, but file was updated: $profile_file"
                                fi
                                update_success=true
                            fi
                        fi
                        
                        if [ "$update_success" = true ]; then
                            log_message "INFO" "Successfully removed Netskope SSL configuration from: $profile_file"
                            removed_from_files=$((removed_from_files + 1))
                        else
                            log_message "ERROR" "Failed to update: $profile_file (permission denied)"
                        fi
                    else
                        log_message "INFO" "Configuration in $profile_file was already clean (no changes needed)"
                    fi
                    rm -f "$temp_profile"
                else
                    log_message "ERROR" "Could not create temporary file for: $profile_file"
                fi
            else
                log_message "INFO" "No Netskope SSL configuration found in: $profile_file - already clean"
            fi
        else
            log_message "DEBUG" "Profile file does not exist: $profile_file"
        fi
    done
    
    log_message "INFO" "Checked $checked_files shell profile file(s) ($existing_files found)"
    
    if [ "$removed_from_files" -gt 0 ]; then
        log_message "INFO" "Successfully removed Netskope SSL configuration from $removed_from_files file(s)"
        log_message "INFO" "Start a new terminal session or run 'unset SSL_CERT_FILE NODE_EXTRA_CA_CERTS REQUESTS_CA_BUNDLE GIT_SSL_CAINFO AWS_CA_BUNDLE DENO_CERT' to clear current session variables"
        return 0
    else
        log_message "INFO" "No Netskope SSL configuration found in any shell profile files - already clean"
        return 0
    fi
}

# Function: cleanup_netskope_directory
# Description: Removes the .netskope directory from user's home (idempotent)
# Returns:
#   0 on success, 1 on failure
function cleanup_netskope_directory() {
    log_message "INFO" "Checking for .netskope directory to clean up..."
    
    # Get the actual user (not root when using sudo)
    local actual_user="${SUDO_USER:-$USER}"
    local actual_home
    actual_home=$(eval echo "~$actual_user")
    local netskope_dir="$actual_home/.netskope"
    
    # Check if directory exists
    if [ -d "$netskope_dir" ]; then
        log_message "INFO" "Found .netskope directory: $netskope_dir"
        
        # List contents before removal for logging
        local file_count=0
        if [ "$(ls -A "$netskope_dir" 2>/dev/null)" ]; then
            file_count=$(find "$netskope_dir" -type f 2>/dev/null | wc -l | tr -d ' ')
            log_message "INFO" "Directory contains $file_count file(s):"
            ls -la "$netskope_dir" 2>/dev/null | while read -r line; do
                log_message "INFO" "  $line"
            done
        else
            log_message "INFO" "Directory is empty"
        fi
        
        # Remove the directory - try user first, then root if needed
        local removal_success=false
        
        # Try as user first
        if sudo -u "$actual_user" rm -rf "$netskope_dir" 2>/dev/null; then
            removal_success=true
        else
            # If user fails, try as root (handles directories/files created by previous sudo runs)
            log_message "INFO" "User permission failed, trying as root for: $netskope_dir"
            if rm -rf "$netskope_dir" 2>/dev/null; then
                removal_success=true
            fi
        fi
        
        if [ "$removal_success" = true ]; then
            log_message "INFO" "Successfully removed directory: $netskope_dir"
            return 0
        else
            log_message "ERROR" "Failed to remove directory: $netskope_dir (permission denied)"
            # Check if it still exists after failed removal
            if [ -d "$netskope_dir" ]; then
                log_message "ERROR" "Directory still exists after removal attempt"
                return 1
            else
                log_message "INFO" "Directory was removed despite error (race condition or permission issue)"
                return 0
            fi
        fi
    elif [ -e "$netskope_dir" ]; then
        # Path exists but is not a directory
        log_message "WARNING" "Path exists but is not a directory: $netskope_dir"
        local file_type
        file_type=$(file "$netskope_dir" 2>/dev/null || echo "unknown type")
        log_message "INFO" "File type: $file_type"
        
        # Try to remove it anyway - try user first, then root if needed
        if sudo -u "$actual_user" rm -rf "$netskope_dir" 2>/dev/null; then
            log_message "INFO" "Successfully removed: $netskope_dir"
            return 0
        elif rm -rf "$netskope_dir" 2>/dev/null; then
            log_message "INFO" "Successfully removed: $netskope_dir (using root permissions)"
            return 0
        else
            log_message "ERROR" "Failed to remove: $netskope_dir (permission denied)"
            return 1
        fi
    else
        log_message "INFO" ".netskope directory does not exist: $netskope_dir - already clean"
        return 0
    fi
}

# Function: cleanup_ssl_cert_directory
# Description: SSL cert directory is now in temp and cleaned automatically (placeholder for compatibility)
# Returns:
#   0 on success
function cleanup_ssl_cert_directory() {
    log_message "INFO" "SSL certificate directory is in temporary location and will be cleaned automatically"
    return 0
}

# Function: show_usage
# Description: Displays usage information with enhanced formatting
function show_usage() {
    show_banner
    echo -e "${BOLD}${GREEN}USAGE:${NC}"
    echo -e "  ${CYAN}curl -fsSL <endpoint> | sudo bash -s -- [OPTIONS]${NC}"
    echo -e "  ${CYAN}$0 [OPTIONS]${NC}"
    echo ""
    echo -e "${BOLD}${GREEN}OPTIONS:${NC}"
    echo -e "  ${YELLOW}-h, --help${NC}              Show this help message"
    # Modes removed; script runs full setup by default
    echo -e "  ${YELLOW}-r, --revert${NC}           Revert Netskope certificates and clean up configuration"
    echo ""
    echo -e "${BOLD}${GREEN}DESCRIPTION:${NC}"
    echo -e "  This script manages Netskope CA certificates and creates a combined"
    echo -e "  CA bundle that includes system certificates and Netskope certificates."
    echo -e "  Certificates are embedded in the script; no network access required."
    echo -e "  Environment variables are automatically configured in your shell."
    echo -e "  No dedicated temporary directory is used; files are written atomically."
    echo ""
    echo -e "${BOLD}${GREEN}EXAMPLES:${NC}"
    echo -e "  ${DIM}curl -fsSL <endpoint> | sudo bash -s --${NC}"
    echo -e "  ${DIM}curl -fsSL <endpoint> | sudo bash -s -- --revert${NC}"
    echo ""
}

# Main function
function main() {
    local create_bundle=false
    local verify_keychain=false
    local update_certifi=false
    local update_gradle_jbr=false
    local remove_cleanup=false
    local show_help=false
    local run_all=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help=true
                shift
                ;;
            -r|--revert)
                remove_cleanup=true
                run_all=false
                shift
                ;;
            *)
                log_message "ERROR" "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    if [ "$show_help" = true ]; then
        show_usage
        exit 0
    fi
    
    # Record start time for execution timing
    local start_time
    start_time=$(date +%s)
    
    echo -e "${BOLD}${WHITE}Setting up secure internet access...${NC}"
    
    # Certificates are embedded; no download step required
    
    # Run all operations by default
    create_bundle=true
    verify_keychain=true
    update_certifi=true
    update_gradle_jbr=true
    
    # Create combined CA bundle
    if [ "$create_bundle" = true ]; then
        print_section_header "Preparing secure certificates" "📦"
        
        # Find system certificate sources
        if find_system_ca_certificates; then
            # Create combined bundle
            if create_combined_ca_bundle; then
                # Validate the bundle
                validate_combined_bundle
                
                # Copy bundle to home directory
                if copy_bundle_to_home; then
                    # Configure shell environment
                    configure_shell_environment
                else
                    log_message "ERROR" "Failed to copy bundle to home directory"
                fi
            else
                log_message "ERROR" "Failed to create combined CA bundle"
            fi
        else
            log_message "WARNING" "No system CA certificate sources found, proceeding with keychain extraction"
            if create_combined_ca_bundle; then
                validate_combined_bundle
                if copy_bundle_to_home; then
                    configure_shell_environment
                else
                    log_message "ERROR" "Failed to copy bundle to home directory"
                fi
            fi
        fi
    fi
    
    # Verify keychain certificates
    if [ "$verify_keychain" = true ]; then
        print_section_header "Checking Mac trust" "🔒"
        
        # Check root CA certificate
        if check_certificate_installation "*.sin2.goskope.com"; then
            log_message "SUCCESS" "Root CA certificate is installed"
            extract_and_verify_trust "*.sin2.goskope.com"
        else
            log_message "ERROR" "Root CA certificate is not installed"
        fi
        
        # Check intermediate CA certificate
        if check_certificate_installation "ca.cashgrail.goskope.com"; then
            log_message "SUCCESS" "Intermediate CA certificate is installed"
            extract_and_verify_trust "ca.cashgrail.goskope.com"
        else
            log_message "ERROR" "Intermediate CA certificate is not installed"
        fi
        
        # Verify certificate chain
        verify_certificate_chain
    fi
    
    # Update certifi bundles
    if [ "$update_certifi" = true ]; then
        print_section_header "Updating application trust settings" "🔄"
        
        # Find certifi cacert.pem files
        if find_certifi_paths; then
            # Update certifi bundles with missing certificates
            update_certifi_bundles
        fi
    fi

    # Update Gradle/Android Studio trust (always)
    if [ "$update_gradle_jbr" = true ]; then
        print_section_header "Updating Android Studio/Gradle trust" "🔧"
        update_gradle_jbr_trust
    fi
    
    # Remove/cleanup Netskope configuration
    if [ "$remove_cleanup" = true ]; then
        print_section_header "Reverting setup" "$CLEAN"
        
        # Get actual user for ownership checks
        local actual_user="${SUDO_USER:-$USER}"
        local cleanup_errors=0
        
        # Find certifi cacert.pem files for cleanup
        if find_certifi_paths; then
            # Remove Netskope certificates from certifi bundles
            if ! remove_certificates_from_certifi; then
                cleanup_errors=$((cleanup_errors + 1))
            fi
        fi
        
        # Remove environment variables from shell profiles
        if ! remove_shell_environment; then
            cleanup_errors=$((cleanup_errors + 1))
        fi
        
        # Clean up .netskope directory
        if ! cleanup_netskope_directory; then
            cleanup_errors=$((cleanup_errors + 1))
        fi
        
        # Clean up ssl-certs directory
        if ! cleanup_ssl_cert_directory; then
            cleanup_errors=$((cleanup_errors + 1))
        fi

        # Remove Gradle JBR trust store entries if present
        remove_gradle_jbr_trust
        
        log_message "SUCCESS" "Netskope configuration cleanup completed"
        
        print_section_header "What we changed" "$CLEAN"
        echo -e "${GREEN}${CHECK_MARK}${NC} Removed Netskope certs from app bundles"
        echo -e "${GREEN}${CHECK_MARK}${NC} Removed certificate settings from your shell"
        echo -e "${GREEN}${CHECK_MARK}${NC} Kept only the main certificate file (~/.netskope/ca-bundle.pem)"
        echo -e "${BLUE}${INFO_SIGN}${NC} You can re-run this script any time"
        
        if [ "$cleanup_errors" -gt 0 ]; then
            echo ""
            log_message "WARNING" "Some cleanup operations encountered errors ($cleanup_errors)"
            echo -e "${YELLOW}${WARNING_SIGN}${NC} This may be due to permission issues with files created during previous runs"
            echo -e "${BLUE}${INFO_SIGN}${NC} The script uses both user and root permissions to handle this automatically"
            echo -e "${BLUE}${INFO_SIGN}${NC} You may need to manually remove any remaining files if errors persist"
        fi
        
        echo ""
        echo -e "${BOLD}${CYAN}🔄 Please restart your terminal to apply changes${NC}"
        echo ""
        return 0
    fi
    
    # Calculate execution time
    local end_time
    end_time=$(date +%s)
    local execution_time=$((end_time - start_time))
    
    # Final summary if combined bundle was created
    if [ "$create_bundle" = true ] && [ -f "$HOME_CACERT_FILE" ]; then
        print_section_header "All set!" "$ROCKET"
        local cert_count
        cert_count=$(grep -c "BEGIN CERTIFICATE" "$HOME_CACERT_FILE" 2>/dev/null || echo 0)
        
        echo -e "${GREEN}${CHECK_MARK}${NC} Combined CA bundle created: ${CYAN}$HOME_CACERT_FILE${NC}"
        echo -e "${GREEN}${CHECK_MARK}${NC} Bundle contains ${BOLD}$cert_count${NC} certificates"
        echo -e "${GREEN}${CHECK_MARK}${NC} Environment variables automatically configured"
        echo -e "${GREEN}${CHECK_MARK}${NC} Shell integration ready"
        echo -e "${BLUE}${INFO_SIGN}${NC} Completed in ${BOLD}${execution_time}s${NC}"
        echo ""
        echo -e "${BOLD}${WHITE}🎉 Setup complete.${NC}"
        echo -e "${CYAN}Please close and reopen all terminal windows and IDEs (Cursor, Android Studio, etc.) to apply trust settings.${NC}"
    fi
}

# Script entry point
main "$@"
