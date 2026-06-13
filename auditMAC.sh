#!/bin/bash
set -u

# ========================================
# macOS Security / Hardening Report
# Author: Bartłomiej
# Version: 2.5
# Developed with assistance from AI tools
# and public security documentation.
# ========================================

clear

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
GRAY='\033[0;90m'
NC='\033[0m'

AUTHOR="Author: Bartłomiej Pogwizd / youtube.com/pTech"
VERSION="Version: 2.5"

TITLE="macOS Security / Audit Report"
LINE="========================================"

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

# ---------- Plik do zbierania wyników ----------
umask 077
DATA_FILE=$(mktemp /tmp/macos_audit_XXXXXX.tsv)
echo -e "label\tstatus\tdetail" > "$DATA_FILE"

# ---------- Funkcje pomocniczne ----------
print_title() {
    echo -e "${BLUE}${LINE}${NC}"
    echo -e "${BLUE}${TITLE}${NC}"
    echo -e "${GRAY}${AUTHOR}${NC}"
    echo -e "${GRAY}${VERSION}${NC}"
    echo -e "${BLUE}${LINE}${NC}"
    echo
}

print_section() {
    echo -e "${BOLD}${CYAN}${1}${NC}"
    echo -e "${CYAN}----------------------------------------${NC}"
}

print_row() {
    local label="$1"
    local status="$2"
    local detail="$3"
    local color="$4"
    printf "%-30s ${color}%-8s${NC} %s\n" "$label" "$status" "$detail"
}

ok() {
    print_row "$1" "OK" "$2" "$GREEN"
    PASS_COUNT=$((PASS_COUNT + 1))
    printf "%s\t%s\t%s\n" "$1" "OK" "$2" >> "$DATA_FILE"
}

warn() {
    print_row "$1" "WARN" "$2" "$YELLOW"
    WARN_COUNT=$((WARN_COUNT + 1))
    printf "%s\t%s\t%s\n" "$1" "WARN" "$2" >> "$DATA_FILE"
}

fail() {
    print_row "$1" "FAIL" "$2" "$RED"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf "%s\t%s\t%s\n" "$1" "FAIL" "$2" >> "$DATA_FILE"
}

info() {
    # INFO wpisy trafiają do TSV/raportów, ale NIE są wliczane do wyniku (score)
    print_row "$1" "INFO" "$2" "$GRAY"
    printf "%s\t%s\t%s\n" "$1" "INFO" "$2" >> "$DATA_FILE"
}

check_contains() {
    local value="$1"
    local needle="$2"
    echo "$value" | grep -qi "$needle"
}

# Bezpieczny odczyt defaults – jeśli brak klucza lub pliku, zwraca podaną wartość domyślną
defaults_read_default() {
    local domain="$1"
    local key="$2"
    local default_val="$3"
    local value
    value=$(defaults read "$domain" "$key" 2>/dev/null)
    if [ -z "$value" ]; then
        echo "$default_val"
    else
        echo "$value"
    fi
}

# Sprawdzenie, czy usługa launchdaemon jest faktycznie wyłączona
is_service_disabled() {
    local service="$1"
    # sprawdź w print-disabled
    if launchctl print-disabled system 2>/dev/null | grep -q "\"$service\" => disabled"; then
        return 0
    fi
    # jeśli nie ma wpisu lub jest enabled, sprawdź czy jest załadowany
    if launchctl list 2>/dev/null | grep -q "$service"; then
        return 1
    fi
    # niezaładowany - traktuj jako wyłączony
    return 0
}

# Sprawdzenie wersji macOS
_MACOS_VER=$(sw_vers -productVersion 2>/dev/null)
MACOS_MAJOR=$(echo "$_MACOS_VER" | cut -d. -f1)
MACOS_MINOR=$(echo "$_MACOS_VER" | cut -d. -f2)

# Sprawdzenie architektury (Apple Silicon vs Intel)
if sysctl -n hw.optional.arm64 2>/dev/null | grep -q "1"; then
    IS_APPLE_SILICON=true
else
    IS_APPLE_SILICON=false
fi

echo -e "${BLUE}Administrator privileges are required for selected security checks.${NC}"
echo -e "${BLUE}sudo access is used locally only and no credentials are stored.${NC}"
echo

# Inicjalizacja sudo i przechwytywanie sygnałów
sudo -v || exit 1

# Odświeżanie tokenu sudo co 60 s (domyślny timeout to 15 min)
while true; do sudo -n true; sleep 60; kill -0 "$$" 2>/dev/null || exit; done &
SUDO_KEEPALIVE_PID=$!

cleanup() {
    echo -e "\n${GRAY}Cleaning up temporary files...${NC}"
    kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
    rm -f "$DATA_FILE" 2>/dev/null
    exit
}
trap cleanup INT TERM EXIT

print_title

# ============================================================
# 1. SYSTEM SECURITY
# ============================================================
print_section "System Security"

# Firewall
STATE=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1)
if echo "$STATE" | grep -qi "enabled"; then
    ok "Firewall" "Enabled"
elif echo "$STATE" | grep -qi "disabled"; then
    fail "Firewall" "Disabled"
else
    fail "Firewall" "Cannot determine (check manually)"
fi

# Secure Boot
STATUS=$(nvram 94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy 2>/dev/null)
if [ -z "$STATUS" ]; then
    info "Secure Boot" "Not applicable on this Mac (Apple Silicon or legacy)"
else
    case "$STATUS" in
        *"%02") ok "Secure Boot" "Full Security" ;;
        *"%01") warn "Secure Boot" "Medium Security" ;;
        *"%00") fail "Secure Boot" "No Security" ;;
        *) warn "Secure Boot" "Unknown value" ;;
    esac
fi

# SIP
OUTPUT=$(csrutil status 2>&1)
if echo "$OUTPUT" | grep -qi "enabled"; then
    ok "SIP" "Enabled"
elif echo "$OUTPUT" | grep -qi "disabled"; then
    fail "SIP" "Disabled"
else
    fail "SIP" "Cannot determine (csrutil error)"
fi

# Authenticated Root
if [ "$MACOS_MAJOR" -ge 11 ] || { [ "$MACOS_MAJOR" -eq 10 ] && [ "$MACOS_MINOR" -ge 15 ]; }; then
    ROOTSTATUS=$(csrutil authenticated-root status 2>/dev/null)
    if echo "$ROOTSTATUS" | grep -qi "enabled"; then
        ok "Authenticated Root" "Enabled"
    else
        fail "Authenticated Root" "Disabled"
    fi
else
    info "Authenticated Root" "Not supported on this macOS"
fi

# System Volume – domyślnie readonly na nowych macOS
if mount | grep "on / " | grep -q "read-only"; then
    ok "System Volume" "Read-only"
elif mount | grep "on / " | grep -q "rw"; then
    fail "System Volume" "Writable"
else
    ok "System Volume" "Read-only (assumed)"
fi

# Gatekeeper – domyślnie włączony
GATEKEEPER=$(spctl --status 2>&1)
if echo "$GATEKEEPER" | grep -qi "enabled"; then
    ok "Gatekeeper" "Enabled"
elif echo "$GATEKEEPER" | grep -qi "disabled"; then
    fail "Gatekeeper" "Disabled"
else
    ok "Gatekeeper" "Enabled (default)"
fi

# Firmware Password – obsługa Apple Silicon
if [ "$IS_APPLE_SILICON" = true ]; then
    if command -v bputil >/dev/null 2>&1; then
        BPUTIL_OUT=$(sudo bputil -d 2>/dev/null | grep -i "Firmware Password" || true)
        if echo "$BPUTIL_OUT" | grep -qi "enabled"; then
            ok "Firmware Password" "Enabled (bputil)"
        elif echo "$BPUTIL_OUT" | grep -qi "disabled"; then
            fail "Firmware Password" "Disabled"
        else
            warn "Firmware Password" "Cannot determine (bputil)"
        fi
    else
        info "Firmware Password" "bputil not found – manual check required"
    fi
else
    FIRMWARE=$(sudo /usr/sbin/firmwarepasswd -check 2>/dev/null)
    if echo "$FIRMWARE" | grep -qi "Yes"; then
        ok "Firmware Password" "Enabled"
    elif echo "$FIRMWARE" | grep -qi "No"; then
        fail "Firmware Password" "Disabled"
    else
        fail "Firmware Password" "Cannot determine (check manually)"
    fi
fi

# FileVault – poprawione użycie sudo
FILEVAULT=$(sudo fdesetup status 2>/dev/null)
if echo "$FILEVAULT" | grep -qi "On"; then
    ok "FileVault" "Enabled"
elif echo "$FILEVAULT" | grep -qi "Off"; then
    fail "FileVault" "Disabled"
else
    fail "FileVault" "Unknown (fdesetup error)"
fi

# ============================================================
# 2. PRIVACY
# ============================================================
print_section "Privacy"


# ============================================================
# Diagnostic Uploads – test wyłącznie informacyjny
# ============================================================



info "Diagnostic Uploads" "Manual verification required: System Settings > Privacy & Security > Analytics & Improvements > Share Mac Analytics"

DIAG_PLIST="/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist"
if [ -f "$DIAG_PLIST" ]; then
    ANA2=$(sudo defaults read "$DIAG_PLIST" ThirdPartyDataSubmit 2>/dev/null)
    if [ "$ANA2" = "0" ]; then
        ok "3rd Party Analytics" "Disabled"
    else
        fail "3rd Party Analytics" "Enabled (default)"
    fi
else
    warn "3rd Party Analytics" "No plist found – assuming enabled (default)"
fi

# Siri Data Sharing – użycie defaults_read_default
ANA3=$(defaults_read_default com.apple.assistant.support "Siri Data Sharing Opt-In Status" "2")
if [ "$ANA3" = "1" ]; then
    fail "Siri Data Sharing" "Enabled"
else
    ok "Siri Data Sharing" "Disabled (default)"
fi

# Secure Token
TOKEN=$(sudo sysadminctl -secureTokenStatus "$(id -un)" 2>&1)
if echo "$TOKEN" | grep -qi "ENABLED"; then
    ok "Secure Token" "Enabled"
elif echo "$TOKEN" | grep -qi "DISABLED"; then
    fail "Secure Token" "Disabled"
else
    fail "Secure Token" "Cannot determine"
fi

# Root Account
RESULT=$(sudo dscl . -read /Users/root AuthenticationAuthority 2>&1)
if echo "$RESULT" | grep -q "No such key\|No such record\|eDSUnknownNodeName"; then
    ok "Root Account" "Disabled"
else
    fail "Root Account" "Enabled"
fi

# Root Visible
if defaults read com.apple.loginwindow ShowRootUser 2>/dev/null | grep -q "^1$"; then
    fail "Root Visible" "Yes"
else
    ok "Root Visible" "No"
fi

# Autologin
RESULT=$(sudo defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>&1)
if echo "$RESULT" | grep -qi "does not exist"; then
    ok "Autologin" "Disabled"
else
    fail "Autologin" "Enabled"
fi

# AirPlay Receiver – domyślnie wyłączony (0)
AP=$(defaults -currentHost read com.apple.controlcenter AirplayReceiverEnabled 2>/dev/null)
if [ "$AP" = "1" ]; then
    fail "AirPlay Receiver" "Enabled"
else
    ok "AirPlay Receiver" "Disabled (default)"
fi

# Location Services – poprawione: find z -quit
LOCATION_PLIST=$(sudo find /private/var/db/locationd/Library/Preferences/ByHost -maxdepth 1 -name "com.apple.locationd.*.plist" -print -quit 2>/dev/null)
if [ -n "$LOCATION_PLIST" ] && [ -f "$LOCATION_PLIST" ]; then
    LOCATION_ENABLED=$(sudo defaults read "$LOCATION_PLIST" LocationServicesEnabled 2>/dev/null)
    if [ "$LOCATION_ENABLED" = "1" ]; then
        fail "Location Services" "Enabled"
    elif [ "$LOCATION_ENABLED" = "0" ]; then
        ok "Location Services" "Disabled"
    else
        warn "Location Services" "Invalid value"
    fi
else
    ok "Location Services" "Disabled (no config)"
fi

# Screen Lock – ujednolicone [ ] zamiast [[ ]]
ASK_PASS=$(defaults_read_default com.apple.screensaver askForPassword "1")
if [ "$ASK_PASS" = "0" ] || [ "$ASK_PASS" = "false" ] || [ "$ASK_PASS" = "NO" ]; then
    fail "Screen Lock" "Disabled"
else
    ok "Screen Lock" "Enabled (default)"
fi

# Touch ID
info "Touch ID" "Automatic check not available – please verify manually in System Settings > Touch ID & Password"
info "Touch ID Unlock" "Manual verification required"
info "Touch ID Apple Pay" "Manual verification required"

# Guest Account
GUEST=$(sudo defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)
if [ "$GUEST" = "1" ]; then
    fail "Guest Account" "Enabled"
else
    ok "Guest Account" "Disabled (default)"
fi

# Guest Share Access
GUEST_SHARE=$(sudo defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess 2>/dev/null)
if [ "$GUEST_SHARE" = "1" ]; then
    fail "Guest Share Access" "Enabled"
else
    ok "Guest Share Access" "Disabled (default)"
fi

# Admin Auth for Settings
AUTH_RESULT=$(sudo security authorizationdb read system.preferences 2>&1 | plutil -convert json - -o - 2>&1)
if echo "$AUTH_RESULT" | grep -q '"shared":true'; then
    fail "Admin Auth for Settings" "Disabled"
else
    ok "Admin Auth for Settings" "Enabled (default)"
fi

# ============================================================
# 3. UPDATES & TIME
# ============================================================
print_section "Updates & Time"

echo -e "${GRAY}Checking for updates (requires internet connection)...${NC}"
UPDATE_OUTPUT=$(softwareupdate -l 2>&1)
if echo "$UPDATE_OUTPUT" | grep -qi "No new software available"; then
    ok "System Updates" "Up to date"
elif echo "$UPDATE_OUTPUT" | grep -qi "Unable to check for updates\|offline"; then
    warn "System Updates" "Check failed (no internet?)"
else
    UPDATE_COUNT=$(echo "$UPDATE_OUTPUT" | grep -c "recommended\|restart" || true)
    if [ "$UPDATE_COUNT" -gt 0 ]; then
        fail "System Updates" "Available ($UPDATE_COUNT updates)"
    else
        warn "System Updates" "Unknown"
    fi
fi

AUTO_DOWNLOAD=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload 2>/dev/null)
if [ "$AUTO_DOWNLOAD" = "1" ]; then
    ok "Auto Download Updates" "Enabled"
else
    fail "Auto Download Updates" "Disabled"
fi

INSTALL_MACOS=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null)
if [ "$INSTALL_MACOS" = "1" ]; then
    ok "Install macOS Updates" "Enabled"
else
    fail "Install macOS Updates" "Disabled"
fi

CRITICAL_UPDATES=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null)
if [ "$CRITICAL_UPDATES" = "1" ]; then
    ok "Critical Updates" "Enabled"
else
    fail "Critical Updates" "Disabled"
fi

RESULT=$(sudo systemsetup -getusingnetworktime 2>&1)
if echo "$RESULT" | grep -qi "Network Time: On"; then
    ok "Network Time" "Enabled"
elif echo "$RESULT" | grep -qi "Network Time: Off"; then
    fail "Network Time" "Disabled"
else
    warn "Network Time" "Unknown"
fi

# Network Metadata – z ostrzeżeniem o zmianach w nowych macOS
NETWORK=$(defaults read com.apple.desktopservices DSDontWriteNetworkStores 2>/dev/null)
if [ "$NETWORK" = "1" ]; then
    ok "Network Metadata" "Blocked"
elif [ "$NETWORK" = "0" ]; then
    fail "Network Metadata" "Allowed (default)"
else
    warn "Network Metadata" "Not set (default allowed) – may not be respected on macOS 14+"
fi

# USB Metadata
USB=$(defaults read com.apple.desktopservices DSDontWriteUSBStores 2>/dev/null)
if [ "$USB" = "1" ]; then
    ok "USB Metadata" "Blocked"
elif [ "$USB" = "0" ]; then
    fail "USB Metadata" "Allowed (default)"
else
    warn "USB Metadata" "Not set (default allowed) – may not be respected on macOS 14+"
fi

RESULT=$(sudo systemsetup -getwakeonnetworkaccess 2>&1)
if echo "$RESULT" | grep -qi "Wake On Network Access: Off"; then
    ok "Wake on Network" "Disabled"
elif echo "$RESULT" | grep -qi "Wake On Network Access: On"; then
    fail "Wake on Network" "Enabled"
else
    warn "Wake on Network" "Unknown"
fi

SUM=$(pmset -g custom | awk '/womp/ { sum+=$2 } END {print sum+0}')
if [ "$SUM" = "0" ]; then
    ok "WOMP" "Disabled"
else
    fail "WOMP" "Enabled"
fi

# Handoff – sprawdzenie obu kluczy
HANDOFF_ADV=$(defaults -currentHost read com.apple.coreservices.useractivityd ActivityAdvertisingAllowed 2>/dev/null)
HANDOFF_RECV=$(defaults -currentHost read com.apple.coreservices.useractivityd ActivityReceivingAllowed 2>/dev/null)
if [ "$HANDOFF_ADV" = "0" ] && [ "$HANDOFF_RECV" = "0" ]; then
    ok "Handoff" "Disabled"
else
    fail "Handoff" "Enabled (default) – advertising: ${HANDOFF_ADV:-1}, receiving: ${HANDOFF_RECV:-1}"
fi

# Universal Control
UC=$(defaults -currentHost read com.apple.universalcontrol Disable 2>/dev/null)
if [ "$UC" = "1" ]; then
    ok "Universal Control" "Disabled"
else
    fail "Universal Control" "Enabled (default)"
fi

# AirDrop
AIRDROP_MODE=$(defaults read ~/Library/Preferences/com.apple.sharingd.plist DiscoverableMode 2>/dev/null)
AWDL_STATUS=$(ifconfig awdl0 2>/dev/null | grep -c "status: active" || true)

if [ "$AIRDROP_MODE" = "Off" ]; then
    ok "AirDrop" "Disabled (DiscoverableMode: Off)"
elif [ "$AIRDROP_MODE" = "Contacts Only" ] || [ "$AIRDROP_MODE" = "Everyone" ]; then
    fail "AirDrop" "Enabled (DiscoverableMode: $AIRDROP_MODE)"
else
    if [ "$AWDL_STATUS" -gt 0 ]; then
        warn "AirDrop" "No DiscoverableMode set, AWDL active – verify manually"
    else
        ok "AirDrop" "Disabled (no config, AWDL inactive)"
    fi
fi

# ============================================================
# 4. SHARING & REMOTE ACCESS
# ============================================================
print_section "Sharing & Remote Access"

SS_DISABLED=$(sudo launchctl print-disabled system 2>/dev/null | grep '"com.apple.screensharing" => true')
if [ -n "$SS_DISABLED" ]; then
    ok "Screen Sharing" "Disabled"
else
    if sudo launchctl list 2>/dev/null | grep -q com.apple.screensharing; then
        fail "Screen Sharing" "Enabled"
    else
        ok "Screen Sharing" "Disabled"
    fi
fi

if sudo launchctl list 2>/dev/null | grep -q smbd; then
    fail "SMB Sharing" "Enabled"
else
    ok "SMB Sharing" "Disabled"
fi

CUPS_OUT=$(sudo cupsctl 2>/dev/null | grep "_share_printers")
if echo "$CUPS_OUT" | grep -q "_share_printers=1"; then
    fail "Printer Sharing" "Enabled"
else
    ok "Printer Sharing" "Disabled (default)"
fi

RESULT=$(sudo systemsetup -getremotelogin 2>&1)
if echo "$RESULT" | grep -qi "Remote Login: Off"; then
    ok "Remote Login" "Disabled"
elif echo "$RESULT" | grep -qi "Remote Login: On"; then
    fail "Remote Login" "Enabled"
else
    warn "Remote Login" "Unknown"
fi

# Remote Management
if [ -f "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart" ]; then
    RM_STATUS=$(sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -check 2>&1)
    if echo "$RM_STATUS" | grep -qi "Enabled: 0"; then
        ok "Remote Management" "Disabled"
    elif echo "$RM_STATUS" | grep -qi "Enabled: 1"; then
        fail "Remote Management" "Enabled"
    else
        if pgrep -q ARDAgent; then
            fail "Remote Management" "Enabled (ARDAgent running)"
        elif [ -f "/var/db/RemoteManagement/com.apple.RemoteManagement.plist" ]; then
            fail "Remote Management" "Enabled (config present)"
        else
            ok "Remote Management" "Disabled (assumed)"
        fi
    fi
else
    if pgrep -q ARDAgent; then
        fail "Remote Management" "Enabled (ARDAgent running)"
    else
        ok "Remote Management" "Disabled (no kickstart)"
    fi
fi

RESULT=$(sudo systemsetup -getremoteappleevents 2>&1)
if echo "$RESULT" | grep -qi "Remote Apple Events: Off"; then
    ok "Remote Apple Events" "Disabled"
elif echo "$RESULT" | grep -qi "Remote Apple Events: On"; then
    fail "Remote Apple Events" "Enabled"
else
    warn "Remote Apple Events" "Unknown"
fi

# AEServer
if is_service_disabled "com.apple.AEServer"; then
    ok "AEServer Daemon" "Disabled"
else
    fail "AEServer Daemon" "Enabled"
fi

# Content Caching
if defaults read /Library/Preferences/com.apple.AssetCache.plist Activated 2>/dev/null | grep -q "1"; then
    fail "Content Caching" "Enabled"
else
    ok "Content Caching" "Disabled (default)"
fi

if sudo launchctl list 2>/dev/null | grep -q com.apple.ODSAgent; then
    fail "ODSAgent" "Enabled"
else
    ok "ODSAgent" "Disabled"
fi

MEDIA=$(defaults read com.apple.amp.mediasharingd home-sharing-enabled 2>/dev/null)
if [ "$MEDIA" = "1" ]; then
    fail "Media Sharing" "Enabled"
else
    ok "Media Sharing" "Disabled (default)"
fi

# ============================================================
# 5. SYSTEM SERVICES
# ============================================================
print_section "System Services"

check_service_disabled() {
    local service="$1"
    local label="$2"
    if is_service_disabled "$service"; then
        ok "$label" "Disabled"
    else
        fail "$label" "Enabled"
    fi
}

check_service_disabled "com.apple.tftpd" "tftpd"
check_service_disabled "com.apple.nfsd" "nfsd"
check_service_disabled "org.apache.httpd" "httpd"
check_service_disabled "com.apple.uucp" "uucp"
check_service_disabled "com.openssh.sshd" "sshd (launchctl)"

# ============================================================
# 6. USERS & PRIVILEGES
# ============================================================
print_section "Users & Privileges"

echo -e "${GREEN}Administrator accounts:${NC}"
sudo dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/GroupMembership: //' | tr ' ' '\n' | while read user; do
    echo "  - $user"
done
echo

if id -nG "$(id -un)" | grep -q -w "admin"; then
    info "Current user" "Is administrator"
else
    info "Current user" "Is standard user"
fi

# ============================================================
# 7. NETWORK & LISTENING PORTS
# ============================================================
print_section "Network & Listening Ports"

echo -e "${GREEN}Open listening ports (IPv4/IPv6):${NC}"
LISTENING_PORTS=$(sudo lsof -i -P -n 2>/dev/null | grep LISTEN | awk '{print $1, $9}' | sort -u)
if [ -n "$LISTENING_PORTS" ]; then
    echo "$LISTENING_PORTS" | while read prog port; do
        echo "  $prog listening on $port"
    done
else
    echo "  No open listening ports found."
fi
echo

echo -e "${GRAY}Active network services (netstat):${NC}"
sudo netstat -anv -p tcp 2>/dev/null | grep -E "LISTEN" | awk '{print $1, $4}' | sort -u | head -10
echo

# ============================================================
# 8. STARTUP ITEMS (LaunchAgents / LaunchDaemons)
# ============================================================
print_section "Startup Items (LaunchAgents/Daemons)"

check_launch_items() {
    local dir="$1"
    local type="$2"
    local is_user="$3"

    if [ -d "$dir" ]; then
        local tmpfile
        tmpfile=$(mktemp /tmp/launch_items.XXXXXX)
        find "$dir" -maxdepth 1 -name "*.plist" 2>/dev/null > "$tmpfile"

        if [ -s "$tmpfile" ]; then
            local count
            count=$(wc -l < "$tmpfile" | tr -d ' ')
            echo -e "${GREEN}${type} (${dir}):${NC}"
            while IFS= read -r plist; do
                basename "$plist"
            done < "$tmpfile"
            echo

            if [ "$is_user" = "yes" ]; then
                if [ "$count" -gt 0 ]; then
                    warn "User LaunchAgents" "$count items present – review manually"
                fi
            else
                info "System ${type}" "$count items present"
            fi
        else
            echo -e "${GRAY}${type} (${dir}): No items found.${NC}"
            echo
        fi

        rm -f "$tmpfile"
    else
        echo -e "${GRAY}${type} (${dir}): Directory does not exist.${NC}"
        echo
    fi
}

check_launch_items "/Library/LaunchAgents"   "System LaunchAgents"  "no"
check_launch_items "/Library/LaunchDaemons"  "System LaunchDaemons" "no"
check_launch_items "$HOME/Library/LaunchAgents" "User LaunchAgents" "yes"

echo -e "${YELLOW}Note: Review the above lists for any unknown or suspicious items.${NC}"
echo

# ============================================================
# 9. SSH HARDENING – bezpieczne użycie sshd -T
# ============================================================
print_section "SSH Hardening"

REMOTE_LOGIN_STATUS=$(sudo systemsetup -getremotelogin 2>&1)
if echo "$REMOTE_LOGIN_STATUS" | grep -qi "Remote Login: On"; then
    echo -e "${YELLOW}Remote Login is ENABLED - checking effective SSH configuration...${NC}"
    if command -v sshd >/dev/null 2>&1; then
        SSH_CONFIG=$(sudo sshd -T 2>/dev/null)
        if [ -n "$SSH_CONFIG" ]; then
            PERMIT_ROOT=$(echo "$SSH_CONFIG" | grep -i "^permitrootlogin" | awk '{print $2}')
            if [ -z "$PERMIT_ROOT" ]; then
                warn "SSH: PermitRootLogin" "Not set (default: prohibit-password)"
            elif [ "$PERMIT_ROOT" = "no" ] || [ "$PERMIT_ROOT" = "prohibit-password" ]; then
                ok "SSH: PermitRootLogin" "$PERMIT_ROOT"
            else
                fail "SSH: PermitRootLogin" "$PERMIT_ROOT (should be no/prohibit-password)"
            fi

            PASS_AUTH=$(echo "$SSH_CONFIG" | grep -i "^passwordauthentication" | awk '{print $2}')
            if [ -z "$PASS_AUTH" ]; then
                warn "SSH: PasswordAuthentication" "Not set (default: yes)"
            elif [ "$PASS_AUTH" = "no" ]; then
                ok "SSH: PasswordAuthentication" "Disabled"
            else
                fail "SSH: PasswordAuthentication" "Enabled (use keys instead)"
            fi

            PUBKEY_AUTH=$(echo "$SSH_CONFIG" | grep -i "^pubkeyauthentication" | awk '{print $2}')
            if [ -z "$PUBKEY_AUTH" ]; then
                warn "SSH: PubkeyAuthentication" "Not set (default: yes)"
            elif [ "$PUBKEY_AUTH" = "yes" ]; then
                ok "SSH: PubkeyAuthentication" "Enabled"
            else
                fail "SSH: PubkeyAuthentication" "Disabled (should be yes)"
            fi

            ALLOW_USERS=$(echo "$SSH_CONFIG" | grep -i "^allowusers" | sed 's/allowusers //i')
            if [ -n "$ALLOW_USERS" ]; then
                info "SSH: AllowUsers" "$ALLOW_USERS"
            else
                info "SSH: AllowUsers" "Not set (any user can connect)"
            fi
        else
            warn "SSH" "Could not parse effective configuration (sshd -T failed)"
        fi
    else
        warn "SSH" "sshd command not found"
    fi
else
    info "SSH" "Remote Login is disabled - skipping detailed SSH configuration check"
fi

# ============================================================
# 10. SYSTEM EXTENSIONS
# ============================================================
print_section "System Extensions"

echo -e "${GREEN}Active system extensions:${NC}"
sudo systemextensionsctl list | grep -E "\[activated.*\]|\[waiting for user.*\]|\[terminated.*\]" || echo "No extensions matching the criteria were found."
echo
echo "If the list includes extensions that are no longer in use or whose origin raises security concerns, remove them immediately."
echo -e "Use: ${GREEN}sudo systemextensionsctl uninstall${NC} <TEAM_ID> <BUNDLE_ID>"
echo

# ============================================================
# 11. SECURITY SCORE
# ============================================================
print_section "Security Score"

TOTAL_CHECKS=$((PASS_COUNT + WARN_COUNT + FAIL_COUNT))
if [ $TOTAL_CHECKS -eq 0 ]; then
    SCORE=0
else
    SCORE=$(( (PASS_COUNT * 100 + WARN_COUNT * 50) / TOTAL_CHECKS ))
fi

printf "%-30s %d/100\n" "Security Score" "$SCORE"

if [ "$SCORE" -ge 80 ]; then
    RISK="Low"
    COLOR="$GREEN"
elif [ "$SCORE" -ge 50 ]; then
    RISK="Medium"
    COLOR="$YELLOW"
else
    RISK="High"
    COLOR="$RED"
fi

echo -e "Risk Level:       ${COLOR}${RISK}${NC}"
echo
printf "%-30s %s\n" "Passed" "$PASS_COUNT"
printf "%-30s %s\n" "Warnings" "$WARN_COUNT"
printf "%-30s %s\n" "Failures" "$FAIL_COUNT"
echo

echo -e "${BLUE}Generating JSON/HTML security reports...${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEN_SCRIPT="$SCRIPT_DIR/generate_reports.sh"

if [ -f "$GEN_SCRIPT" ] && [ -x "$GEN_SCRIPT" ]; then
    "$GEN_SCRIPT" "$DATA_FILE" "macos_security_report.json" "macos_security_report.html"
    echo -e "${GREEN}✓ Reports saved: macos_security_report.json, macos_security_report.html${NC}"
else
    echo -e "${YELLOW}⚠ Warning: generate_reports.sh not found or not executable in $SCRIPT_DIR${NC}"
    echo -e "${YELLOW}  Place generate_reports.sh in the same directory and make it executable (chmod +x).${NC}"
    echo -e "${YELLOW}  Raw audit data file: $DATA_FILE (will be removed on exit).${NC}"
fi

echo

# ============================================================
# KONIEC
# ============================================================
