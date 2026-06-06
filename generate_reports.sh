#!/bin/bash

# ============================================
# Generator raportów JSON/HTML z audytu macOS
# Kompatybilny z Bash 3.2 (macOS domyślnie)
# ============================================

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Użycie: $0 <ścieżka_do_pliku_tsv> [json_output] [html_output]"
    echo "Przykład: $0 /tmp/macos_audit_12345.tsv"
    exit 1
fi

DATA_FILE="$1"
OUT_JSON="${2:-macos_security_report.json}"
OUT_HTML="${3:-macos_security_report.html}"

if [ ! -f "$DATA_FILE" ]; then
    echo "Plik z danymi nie istnieje: $DATA_FILE"
    exit 1
fi

# ------------------------------------------
# Funkcja mapująca etykietę na identyfikator CIS
# ------------------------------------------
get_cis_id() {
    local label="$1"
    case "$label" in
        "Firewall")                 echo "2.1.1" ;;
        "Secure Boot")              echo "5.1.1" ;;
        "SIP")                      echo "5.1.2" ;;
        "Authenticated Root")       echo "5.1.3" ;;
        "System Volume")            echo "5.1.3" ;;
        "Gatekeeper")               echo "2.4.1" ;;
        "Firmware Password")        echo "5.1.7" ;;
        "FileVault")                echo "2.2.1" ;;
        "Diagnostic Uploads")       echo "2.11.1" ;;
        "3rd Party Analytics")      echo "2.11.2" ;;
        "Siri Data Sharing")        echo "2.5.1" ;;
        "Secure Token")             echo "5.2.1" ;;
        "Root Account")             echo "5.2.2" ;;
        "Root Visible")             echo "5.2.2" ;;
        "Autologin")                echo "5.4.1" ;;
        "AirPlay Receiver")         echo "2.3.2" ;;
        "Location Services")        echo "2.6.1" ;;
        "Screen Lock")              echo "2.7.1" ;;
        "Touch ID Unlock")          echo "5.2.3" ;;
        "Touch ID Apple Pay")       echo "5.2.3" ;;
        "Guest Account")            echo "5.3.1" ;;
        "Guest Share Access")       echo "2.10.2" ;;
        "Admin Auth for Settings")  echo "5.8.1" ;;
        "System Updates")           echo "1.1" ;;
        "Auto Download Updates")    echo "1.2" ;;
        "Install macOS Updates")    echo "1.3" ;;
        "Critical Updates")         echo "1.5" ;;
        "Network Time")             echo "2.8.1" ;;
        "Network Metadata")         echo "2.9.1" ;;
        "USB Metadata")             echo "2.9.2" ;;
        "Wake on Network")          echo "2.10.1" ;;
        "WOMP")                     echo "2.10.1" ;;
        "Handoff")                  echo "2.3.1" ;;
        "Universal Control")        echo "2.3.3" ;;
        "AirDrop")                  echo "2.3.1" ;;
        "Screen Sharing")           echo "2.2.2" ;;
        "SMB Sharing")              echo "2.2.3" ;;
        "Printer Sharing")          echo "2.2.4" ;;
        "Remote Login")             echo "2.2.5" ;;
        "Remote Management")        echo "2.2.6" ;;
        "Remote Apple Events")      echo "2.2.7" ;;
        "AEServer Daemon")          echo "2.2.8" ;;
        "Content Caching")          echo "2.2.9" ;;
        "ODSAgent")                 echo "2.2.10" ;;
        "Media Sharing")            echo "2.2.11" ;;
        "tftpd")                    echo "2.1.2" ;;
        "nfsd")                     echo "2.1.3" ;;
        "httpd")                    echo "2.1.4" ;;
        "uucp")                     echo "2.1.5" ;;
        "sshd (launchctl)")          echo "2.1.6" ;;
        "SSH: PermitRootLogin")     echo "5.2.9" ;;
        "SSH: PasswordAuthentication") echo "5.2.10" ;;
        "SSH: PubkeyAuthentication")   echo "5.2.11" ;;
        "SSH: AllowUsers")          echo "5.2.12" ;;
        *)                          echo "" ;;
    esac
}

# Liczniki
PASS=0
WARN=0
FAIL=0

# Tymczasowy plik na elementy JSON
JSON_TMP=$(mktemp /tmp/json_items.XXXXXX)
trap 'rm -f "$JSON_TMP"' EXIT INT TERM

# Wczytaj plik TSV
while IFS=$'\t' read -r label status detail; do
    # Pomiń nagłówek
    [ "$label" = "label" ] && continue

    # Pobierz ID CIS
    cis_id=$(get_cis_id "$label")

    # Liczniki
    case "$status" in
        OK)   PASS=$((PASS+1)) ;;
        WARN) WARN=$((WARN+1)) ;;
        FAIL) FAIL=$((FAIL+1)) ;;
    esac

    # Bezpieczne cytowanie do JSON (tylko podstawowe znaki)
    escaped_detail=$(echo "$detail" | sed 's/\\/\\\\/g; s/"/\\"/g')
    printf '{"label":"%s","status":"%s","detail":"%s","cis_id":"%s"}\n' \
        "$label" "$status" "$escaped_detail" "$cis_id" >> "$JSON_TMP"
done < "$DATA_FILE"

# Oblicz wynik
TOTAL=$((PASS+WARN+FAIL))
if [ "$TOTAL" -eq 0 ]; then
    SCORE=0
else
    SCORE=$(( (PASS*100 + WARN*50) / TOTAL ))
fi

if [ "$SCORE" -ge 80 ]; then
    RISK="Low"
    RISK_CLASS="risk-low"
elif [ "$SCORE" -ge 50 ]; then
    RISK="Medium"
    RISK_CLASS="risk-medium"
else
    RISK="High"
    RISK_CLASS="risk-high"
fi

# ----------------------
# Generowanie JSON
# ----------------------
echo "Generowanie $OUT_JSON ..."
{
    echo '{'
    echo "  \"title\": \"macOS Security / Audit Report\","
    echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
    echo "  \"score\": $SCORE,"
    echo "  \"risk_level\": \"$RISK\","
    echo "  \"counts\": {"
    echo "    \"passed\": $PASS,"
    echo "    \"warnings\": $WARN,"
    echo "    \"failures\": $FAIL"
    echo "  },"
    echo '  "results": ['
    # Połącz linie przecinkami
    FIRST=true
    while IFS= read -r line; do
        if [ "$FIRST" = true ]; then
            FIRST=false
        else
            echo ","
        fi
        printf "    %s" "$line"
    done < "$JSON_TMP"
    echo ""
    echo '  ]'
    echo '}'
} > "$OUT_JSON"

# ----------------------
# Generowanie HTML
# ----------------------
echo "Generowanie $OUT_HTML ..."
cat > "$OUT_HTML" << EOF
<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<title>macOS Security Report</title>
<style>
body { font-family: -apple-system, sans-serif; margin: 20px; background: #fff; color: #222; }
h1 { color: #1d1d1f; }
table { border-collapse: collapse; width: 100%; margin-top: 20px; }
th { background: #f5f5f7; }
td, th { border: 1px solid #d2d2d7; padding: 6px 12px; text-align: left; }
.ok { color: #007D3A; font-weight: bold; }
.warn { color: #FF9500; font-weight: bold; }
.fail { color: #FF3B30; font-weight: bold; }
.info { color: #8e8e93; }
.score { font-size: 24px; }
.risk-low { color: #007D3A; }
.risk-medium { color: #FF9500; }
.risk-high { color: #FF3B30; }
</style>
</head>
<body>
<h1>macOS Security / Audit Report</h1>
<p><em>Wygenerowano: $(date)</em></p>
<div>Wynik: <span class="score">$SCORE/100</span> (<span class="$RISK_CLASS">$RISK</span>)</div>
<p>✅ Zaliczonych: $PASS | ⚠️ Ostrzeżeń: $WARN | ❌ Błędów: $FAIL</p>
<table>
<tr><th>Kontrola</th><th>Status</th><th>Szczegóły</th><th>CIS ID</th></tr>
EOF

while IFS=$'\t' read -r label status detail; do
    [ "$label" = "label" ] && continue
    cis_id=$(get_cis_id "$label")
    escaped_detail=$(echo "$detail" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
    cssclass="info"
    case "$status" in
        OK)   cssclass="ok" ;;
        WARN) cssclass="warn" ;;
        FAIL) cssclass="fail" ;;
    esac
    echo "<tr><td>$label</td><td class=\"$cssclass\">$status</td><td>$escaped_detail</td><td>$cis_id</td></tr>" >> "$OUT_HTML"
done < "$DATA_FILE"

echo "</table></body></html>" >> "$OUT_HTML"

# Posprzątaj (obsługiwane przez trap EXIT)

echo "Gotowe! Raporty zapisane:"
echo "  JSON: $OUT_JSON"
echo "  HTML: $OUT_HTML"