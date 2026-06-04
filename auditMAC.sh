#!/bin/bash

# ========================================
# macOS Security / Audit Report
# Author: Bartłomiej
# Version: 1.1
# Developed with assistance from AI tools
# and public security documentation.
# ========================================

clear

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
GRAY='\033[0;90m'
NC='\033[0m'

AUTHOR="Author: Bartłomiej Pogwizd / youtube.com/pTech"
VERSION="Version: 1.1"

TITLE="macOS Security / Audit Report"
LINE="========================================"

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

print_title() {
    echo -e "${BLUE}${LINE}${NC}"
    echo -e "${BLUE}${TITLE}${NC}"
    echo -e "${GRAY}${AUTHOR}${NC}"
    echo -e "${GRAY}${VERSION}${NC}"
    echo -e "${BLUE}${LINE}${NC}"
    echo
}

print_section() {
    echo -e "${GRAY}${1}${NC}"
    echo -e "${GRAY}----------------------------------------${NC}"
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
}

warn() {
    print_row "$1" "WARN" "$2" "$YELLOW"
    WARN_COUNT=$((WARN_COUNT + 1))
}

fail() {
    print_row "$1" "FAIL" "$2" "$RED"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

info() {
    print_row "$1" "INFO" "$2" "$GRAY"
}

check_contains() {
    local value="$1"
    local needle="$2"
    echo "$value" | grep -qi "$needle"
}

# Sprawdzenie wersji macOS
macos_version() {
    sw_vers -productVersion 2>/dev/null
}
MACOS_MAJOR=$(macos_version | cut -d. -f1)
MACOS_MINOR=$(macos_version | cut -d. -f2)

echo -e "${BLUE}Administrator privileges are required for selected security checks.${NC}"
echo -e "${BLUE}sudo access is used locally only and no credentials are stored.${NC}"
echo

sudo -v || exit 1
while true; do sudo -v; sleep 300; done &
SUDO_KEEP_ALIVE=$!

cleanup() {
    kill "$SUDO_KEEP_ALIVE" 2>/dev/null
}
trap cleanup EXIT

print_title

print_section "System Security"

STATE=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
if check_contains "$STATE" "enabled"; then
    ok "Firewall" "Enabled"
elif check_contains "$STATE" "disabled"; then
    fail "Firewall" "Disabled"
else
    warn "Firewall" "Unknown"
fi

STATUS=$(nvram 94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy 2>/dev/null)
if [ -z "$STATUS" ]; then
    warn "Secure Boot" "Unsupported / unavailable"
else
    case "$STATUS" in
        *"%02") ok "Secure Boot" "Full Security" ;;
        *"%01") warn "Secure Boot" "Medium Security" ;;
        *"%00") fail "Secure Boot" "No Security" ;;
        *) warn "Secure Boot" "Unknown" ;;
    esac
fi

OUTPUT=$(csrutil status 2>&1)
if check_contains "$OUTPUT" "enabled"; then
    ok "SIP" "Enabled"
elif check_contains "$OUTPUT" "disabled"; then
    fail "SIP" "Disabled"
else
    warn "SIP" "Unreadable"
fi

if [ "$MACOS_MAJOR" -ge 11 ] || [ "$MACOS_MAJOR" -eq 10 -a "$MACOS_MINOR" -ge 15 ]; then
    ROOTSTATUS=$(csrutil authenticated-root status 2>/dev/null)
    if check_contains "$ROOTSTATUS" "enabled"; then
        ok "Authenticated Root" "Enabled"
    else
        fail "Authenticated Root" "Disabled"
    fi
else
    info "Authenticated Root" "Not supported on this macOS"
fi

# Sprawdzenie, czy wolumin systemowy jest tylko do odczytu (lepsza metoda)
if mount | grep "on / " | grep -q "read-only"; then
    ok "System Volume" "Read-only"
elif mount | grep "on / " | grep -q "rw"; then
    fail "System Volume" "Writable"
else
    warn "System Volume" "Unknown"
fi

GATEKEEPER=$(spctl --status 2>/dev/null)
if check_contains "$GATEKEEPER" "enabled"; then
    ok "Gatekeeper" "Enabled"
elif check_contains "$GATEKEEPER" "disabled"; then
    fail "Gatekeeper" "Disabled"
else
    warn "Gatekeeper" "Unknown"
fi

FIRMWARE=$(sudo /usr/sbin/firmwarepasswd -check 2>/dev/null)
if check_contains "$FIRMWARE" "Yes"; then
    ok "Firmware Password" "Enabled"
elif check_contains "$FIRMWARE" "No"; then
    fail "Firmware Password" "Disabled"
else
    warn "Firmware Password" "Unknown / Intel only"
fi

FILEVAULT=$(fdesetup status -extended 2>/dev/null)
if check_contains "$FILEVAULT" "On"; then
    ok "FileVault" "Enabled"
elif check_contains "$FILEVAULT" "Off"; then
    fail "FileVault" "Disabled"
else
    warn "FileVault" "Unknown"
fi

print_section "Privacy"

# Poprawka: dodano sudo dla obu odczytów
ANA1=$(sudo defaults read /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit 2>/dev/null)
if [ "$ANA1" = "1" ]; then
    fail "Diagnostic Uploads" "Enabled"
elif [ "$ANA1" = "0" ]; then
    ok "Diagnostic Uploads" "Disabled"
else
    warn "Diagnostic Uploads" "Unknown"
fi

ANA2=$(sudo defaults read /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist ThirdPartyDataSubmit 2>/dev/null)
if [ "$ANA2" = "1" ]; then
    fail "3rd Party Analytics" "Enabled"
elif [ "$ANA2" = "0" ]; then
    ok "3rd Party Analytics" "Disabled"
else
    warn "3rd Party Analytics" "Unknown"
fi

ANA3=$(defaults read ~/Library/Preferences/com.apple.assistant.support "Siri Data Sharing Opt-In Status" 2>/dev/null)
if [ "$ANA3" = "2" ]; then
    ok "Siri Data Sharing" "Disabled"
elif [ "$ANA3" = "1" ]; then
    fail "Siri Data Sharing" "Enabled"
else
    warn "Siri Data Sharing" "Unknown"
fi

TOKEN=$(sudo sysadminctl -secureTokenStatus "$(id -un)" 2>&1)
if check_contains "$TOKEN" "ENABLED"; then
    ok "Secure Token" "Enabled"
elif check_contains "$TOKEN" "DISABLED"; then
    fail "Secure Token" "Disabled"
else
    warn "Secure Token" "Unknown"
fi

RESULT=$(sudo dscl . -read /Users/root AuthenticationAuthority 2>&1)
if check_contains "$RESULT" "No such key"; then
    ok "Root Account" "Disabled"
else
    fail "Root Account" "Enabled"
fi

if defaults read com.apple.loginwindow ShowRootUser 2>/dev/null | grep -q "^1$"; then
    fail "Root Visible" "Yes"
else
    ok "Root Visible" "No"
fi

RESULT=$(sudo defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>&1)
if check_contains "$RESULT" "does not exist"; then
    ok "Autologin" "Disabled"
else
    fail "Autologin" "Enabled"
fi

RESULT=$(defaults -currentHost read com.apple.controlcenter AirplayReceiverEnabled 2>/dev/null)
if [ "$RESULT" = "0" ]; then
    ok "AirPlay Receiver" "Disabled"
else
    fail "AirPlay Receiver" "Enabled"
fi

RESULT=$(sudo find /private/var/db/locationd/Library/Preferences/ByHost \
-name "com.apple.locationd.*.plist" \
-exec defaults read {} LocationServicesEnabled \; 2>/dev/null | grep -c 1)
if [ "$RESULT" = "0" ]; then
    ok "Location Services" "Disabled"
else
    fail "Location Services" "Enabled"
fi

# POPRAWIONE sprawdzanie blokady ekranu (zamiast sysadminctl -screenLock)
ASK_PASS=$(defaults read com.apple.screensaver askForPassword 2>/dev/null)
DELAY=$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null)
if [ "$ASK_PASS" = "1" ]; then
    ok "Screen Lock" "Enabled (delay ${DELAY:-0} sec)"
elif [ "$ASK_PASS" = "0" ]; then
    fail "Screen Lock" "Disabled"
else
    warn "Screen Lock" "Unknown (default may be enabled)"
fi

RESULT=$(bioutil -r 2>&1)
if echo "$RESULT" | grep -q "Touch ID does not exist"; then
    info "Touch ID" "Not available"
else
    UNLOCK=$(echo "$RESULT" | grep -oE "Biometrics for unlock: [0-9]" | grep -oE "[0-9]")
    UNLOCK_EFF=$(echo "$RESULT" | grep -oE "Effective biometrics for unlock: [0-9]" | grep -oE "[0-9]")
    APPLEPAY=$(echo "$RESULT" | grep -oE "Biometrics for ApplePay: [0-9]" | grep -oE "[0-9]")
    APPLEPAY_EFF=$(echo "$RESULT" | grep -oE "Effective biometrics for ApplePay: [0-9]" | grep -oE "[0-9]")

    if [ "$UNLOCK" = "0" ] && [ "$UNLOCK_EFF" = "0" ] && [ "$APPLEPAY" = "0" ] && [ "$APPLEPAY_EFF" = "0" ]; then
        warn "Touch ID" "Disabled"
    else
        if [ "$UNLOCK" -ge 1 ] && [ "$UNLOCK" -le 5 ] && [ "$UNLOCK_EFF" -ge 1 ] && [ "$UNLOCK_EFF" -le 5 ]; then
            ok "Touch ID Unlock" "Enabled"
        else
            fail "Touch ID Unlock" "Disabled"
        fi

        if [ "$APPLEPAY" -ge 1 ] && [ "$APPLEPAY" -le 5 ] && [ "$APPLEPAY_EFF" -ge 1 ] && [ "$APPLEPAY_EFF" -le 5 ]; then
            fail "Touch ID Apple Pay" "Enabled"
        else
            ok "Touch ID Apple Pay" "Disabled"
        fi
    fi
fi

RESULT=$(sudo defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>&1)
if [ "$RESULT" = "0" ]; then
    ok "Guest Account" "Disabled"
elif [ "$RESULT" = "1" ]; then
    fail "Guest Account" "Enabled"
else
    warn "Guest Account" "Unknown"
fi

RESULT=$(sudo defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess 2>&1)
if [ "$RESULT" = "1" ]; then
    fail "Guest Share Access" "Enabled"
elif [ "$RESULT" = "0" ]; then
    ok "Guest Share Access" "Disabled"
else
    warn "Guest Share Access" "Unknown"
fi

RESULT=$(sudo security authorizationdb read system.preferences 2>&1 | plutil -convert json - -o - 2>&1)
if echo "$RESULT" | grep -q '"shared":true'; then
    fail "Admin Auth for Settings" "Disabled"
elif echo "$RESULT" | grep -q '"shared":false'; then
    ok "Admin Auth for Settings" "Enabled"
else
    warn "Admin Auth for Settings" "Unknown"
fi

print_section "Updates & Time"

# Sprawdzenie aktualizacji systemu - z ostrzeżeniem o wymaganym internecie
echo -e "${GRAY}Checking for updates (requires internet connection)...${NC}"
UPDATE_OUTPUT=$(softwareupdate -l 2>&1)
if check_contains "$UPDATE_OUTPUT" "No new software available"; then
    ok "System Updates" "Up to date"
elif check_contains "$UPDATE_OUTPUT" "Unable to check for updates" || check_contains "$UPDATE_OUTPUT" "offline"; then
    warn "System Updates" "Check failed (no internet?)"
else
    UPDATE_COUNT=$(echo "$UPDATE_OUTPUT" | grep -c "recommended\|restart" || true)
    if [ "$UPDATE_COUNT" -gt 0 ]; then
        fail "System Updates" "Available ($UPDATE_COUNT updates)"
    else
        warn "System Updates" "Unknown"
    fi
fi

# Poprawione odczytywanie ustawień aktualizacji - bezpośrednie klucze
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
if check_contains "$RESULT" "Network Time: On"; then
    ok "Network Time" "Enabled"
elif check_contains "$RESULT" "Network Time: Off"; then
    fail "Network Time" "Disabled"
else
    warn "Network Time" "Unknown"
fi

NETWORK=$(defaults read com.apple.desktopservices DSDontWriteNetworkStores 2>/dev/null)
: "${NETWORK:=0}"
if [ "$NETWORK" = "1" ]; then
    ok "Network Metadata" "Blocked"
else
    fail "Network Metadata" "Allowed"
fi

USB=$(defaults read com.apple.desktopservices DSDontWriteUSBStores 2>/dev/null)
: "${USB:=0}"
if [ "$USB" = "1" ]; then
    ok "USB Metadata" "Blocked"
else
    fail "USB Metadata" "Allowed"
fi

RESULT=$(sudo systemsetup -getwakeonnetworkaccess 2>&1)
if check_contains "$RESULT" "Wake On Network Access: Off"; then
    ok "Wake on Network" "Disabled"
elif check_contains "$RESULT" "Wake On Network Access: On"; then
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

RESULT=$(defaults -currentHost read com.apple.coreservices.useractivityd ActivityAdvertisingAllowed 2>/dev/null)
if [ "$RESULT" = "0" ]; then
    ok "Handoff" "Disabled"
else
    fail "Handoff" "Enabled"
fi

RESULT=$(defaults -currentHost read com.apple.universalcontrol Disable 2>/dev/null)
if [ "$RESULT" = "1" ]; then
    ok "Universal Control" "Disabled"
else
    fail "Universal Control" "Enabled"
fi

RESULT=$(defaults read com.apple.NetworkBrowser DisableAirDrop 2>/dev/null)
if [ "$RESULT" = "1" ]; then
    ok "AirDrop" "Disabled"
else
    fail "AirDrop" "Enabled"
fi

print_section "Sharing & Remote Access"

# Poprawione sprawdzanie Screen Sharing przez launchctl print-disabled
SS_DISABLED=$(sudo launchctl print-disabled system 2>/dev/null | grep '"com.apple.screensharing" => true')
if [ -n "$SS_DISABLED" ]; then
    ok "Screen Sharing" "Disabled"
else
    # dodatkowe sprawdzenie czy w ogóle załadowany
    if sudo launchctl list 2>/dev/null | grep -q com.apple.screensharing; then
        fail "Screen Sharing" "Enabled"
    else
        ok "Screen Sharing" "Disabled"
    fi
fi

RESULT=$(sudo launchctl list 2>/dev/null | grep smbd)
if [ -z "$RESULT" ]; then
    ok "SMB Sharing" "Disabled"
else
    fail "SMB Sharing" "Enabled"
fi

RESULT=$(sudo cupsctl 2>/dev/null | grep "_share_printers")
if echo "$RESULT" | grep -q "_share_printers=0"; then
    ok "Printer Sharing" "Disabled"
elif echo "$RESULT" | grep -q "_share_printers=1"; then
    fail "Printer Sharing" "Enabled"
else
    warn "Printer Sharing" "Unknown"
fi

RESULT=$(sudo systemsetup -getremotelogin 2>&1)
if check_contains "$RESULT" "Remote Login: Off"; then
    ok "Remote Login" "Disabled"
elif check_contains "$RESULT" "Remote Login: On"; then
    fail "Remote Login" "Enabled"
else
    warn "Remote Login" "Unknown"
fi

# Poprawione sprawdzanie Remote Management (ARDAgent)
if [ -f "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart" ]; then
    RM_STATUS=$(sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -check 2>&1)
    if echo "$RM_STATUS" | grep -q "Enabled: 0"; then
        ok "Remote Management" "Disabled"
    elif echo "$RM_STATUS" | grep -q "Enabled: 1"; then
        fail "Remote Management" "Enabled"
    else
        warn "Remote Management" "Unknown"
    fi
else
    # fallback - sprawdzenie procesu
    if sudo ps -ef | grep -v grep | grep -q ARDAgent; then
        fail "Remote Management" "Possibly enabled (ARDAgent running)"
    else
        ok "Remote Management" "Disabled (no kickstart)"
    fi
fi

RESULT=$(sudo systemsetup -getremoteappleevents 2>&1)
if check_contains "$RESULT" "Remote Apple Events: Off"; then
    ok "Remote Apple Events" "Disabled"
else
    fail "Remote Apple Events" "Enabled"
fi

RESULT=$(launchctl print-disabled system 2>/dev/null | grep com.apple.AEServer)
if echo "$RESULT" | grep -q '"com.apple.AEServer" => disabled'; then
    ok "AEServer Daemon" "Disabled"
else
    fail "AEServer Daemon" "Enabled"
fi

RESULT=$(defaults read /Library/Preferences/com.apple.AssetCache.plist 2>/dev/null | grep Activated)
if echo "$RESULT" | grep -q "Activated = 0"; then
    ok "Content Caching" "Disabled"
else
    fail "Content Caching" "Enabled"
fi

COUNT=$(sudo launchctl list 2>/dev/null | grep -c com.apple.ODSAgent)
if [ "$COUNT" = "0" ]; then
    ok "ODSAgent" "Disabled"
else
    fail "ODSAgent" "Enabled"
fi

RESULT=$(defaults read com.apple.amp.mediasharingd home-sharing-enabled 2>/dev/null)
if [ "$RESULT" = "0" ]; then
    ok "Media Sharing" "Disabled"
else
    fail "Media Sharing" "Enabled"
fi

print_section "System Services"

COUNT_TFTP=$(launchctl print-disabled system 2>/dev/null | grep -c '"com.apple.tftpd" => true')
if [ "$COUNT_TFTP" = "1" ]; then
    ok "tftpd" "Disabled"
else
    fail "tftpd" "Enabled"
fi

COUNT_NFS=$(launchctl print-disabled system 2>/dev/null | grep -c '"com.apple.nfsd" => true')
if [ "$COUNT_NFS" = "1" ]; then
    ok "nfsd" "Disabled"
else
    fail "nfsd" "Enabled"
fi

COUNT_HTTP=$(launchctl print-disabled system 2>/dev/null | grep -c '"org.apache.httpd" => true')
if [ "$COUNT_HTTP" = "1" ]; then
    ok "httpd" "Disabled"
else
    fail "httpd" "Enabled"
fi

COUNT_UUCP=$(launchctl print-disabled system 2>/dev/null | grep -c '"com.apple.uucp" => true')
if [ "$COUNT_UUCP" = "1" ]; then
    ok "uucp" "Disabled"
else
    fail "uucp" "Enabled"
fi

COUNT_SSH=$(launchctl print-disabled system 2>/dev/null | grep -c '"com.openssh.sshd" => true')
if [ "$COUNT_SSH" = "1" ]; then
    ok "sshd" "Disabled"
else
    fail "sshd" "Enabled"
fi

print_section "System Extensions"

echo -e "${GREEN}Active system extensions:${NC}"
systemextensionsctl list | grep -E "\[activated.*\]|\[waiting for user.*\]|\[terminated.*\]" || echo "No extensions matching the criteria were found."
echo

echo "If the list includes extensions that are no longer in use or whose origin raises security concerns, remove them immediately."
echo -e "Use: ${GREEN}sudo systemextensionsctl uninstall${NC} <TEAM_ID> <BUNDLE_ID>"
echo

print_section "Summary"
printf "%-30s %s\n" "Passed" "$PASS_COUNT"
printf "%-30s %s\n" "Warnings" "$WARN_COUNT"
printf "%-30s %s\n" "Failures" "$FAIL_COUNT"
echo
