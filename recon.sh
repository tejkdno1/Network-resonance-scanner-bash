#!/bin/bash
TARGETS_FILE="targets.txt"
PORTS_FILE="common-ports.txt"
WEB_PATHS_FILE="web-paths.txt"
WORDLIST_FILE="wordlist.txt"
OUTPUT_DIR="scan_results"
SSH_CREDS=("root:password" "admin:admin" "admin:password")
mkdir -p "$OUTPUT_DIR"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
check_requirements() {
    local tools=("nmap" "curl" "nc" "ssh")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${RED}[ERROR] $tool is not installed${NC}"
            exit 1
        fi
    done
}
ping_sweep() {
    local network=$1
    echo -e "${YELLOW}[*] Performing ping sweep on $network${NC}"
    nmap -sn "$network" -oG - | awk '/Up$/{print $2}' > "$OUTPUT_DIR/live_hosts.txt"
    echo -e "${GREEN}[+] Found $(wc -l < "$OUTPUT_DIR/live_hosts.txt") live hosts${NC}"
}
scan_ports() {
    local host=$1
    echo -e "${YELLOW}[*] Scanning ports on $host${NC}"
    while read -r port; do
        if nc -z -w1 "$host" "$port" &>/dev/null; then
            service=$(nmap -sV -p "$port" "$host" 2>/dev/null | grep open | awk '{print $3}')
            echo -e "${GREEN}[+] Port $port/tcp open ($service)${NC}"
            echo "$host:$port:$service" >> "$OUTPUT_DIR/open_ports.txt"
            
            # Service-specific checks
            case "$port" in
                22) check_ssh "$host" ;;
                21) check_ftp "$host" ;;
                80|443|8080) check_web "$host" "$port" ;;
            esac
        fi
    done < "$PORTS_FILE"
}
check_ssh() {
    local host=$1
    echo -e "${YELLOW}[*] Checking SSH default credentials on $host${NC}"
    
    for cred in "${SSH_CREDS[@]}"; do
        IFS=':' read -r user pass <<< "$cred"
        if sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$user@$host" exit 2>/dev/null; then
            echo -e "${RED}[!] Default SSH credentials found: $user:$pass${NC}"
            echo "SSH_DEFAULT_CREDS:$user:$pass" >> "$OUTPUT_DIR/vulnerabilities.txt"
            return
        fi
    done
}
check_ftp() {
    local host=$1
    echo -e "${YELLOW}[*] Checking anonymous FTP on $host${NC}"
    
    if echo "USER anonymous" | nc -w 2 "$host" 21 | grep -q "230"; then
        echo -e "${RED}[!] Anonymous FTP access allowed${NC}"
        echo "FTP_ANONYMOUS_ACCESS" >> "$OUTPUT_DIR/vulnerabilities.txt"
    fi
}
check_web() {
    local host=$1
    local port=$2
    echo -e "${YELLOW}[*] Checking web vulnerabilities on $host:$port${NC}"
    while read -r path; do
        url="http://$host:$port/$path"
        status_code=$(curl -o /dev/null -s -w "%{http_code}" "$url")
        
        if [ "$status_code" == "200" ]; then
            echo -e "${GREEN}[+] Found: $url ($status_code)${NC}"
            echo "WEB_DEFAULT_PAGE:$url" >> "$OUTPUT_DIR/vulnerabilities.txt"
        fi
    done < "$WEB_PATHS_FILE"
    if curl -s "http://$host:$port/" | grep -q "Index of"; then
        echo -e "${RED}[!] Directory listing enabled${NC}"
        echo "WEB_DIR_LISTING:$host:$port" >> "$OUTPUT_DIR/vulnerabilities.txt"
    fi
}
main() {
    echo -e "${GREEN}=== Basic Network Reconnaissance Scanner ===${NC}"
    echo -e "${RED}FOR EDUCATIONAL USE ONLY${NC}"
    echo -e "${RED}SCAN ONLY SYSTEMS YOU OWN${NC}"
    echo ""
    
    check_requirements
    while IFS= read -r target; do
        [[ -z "$target" || "$target" == \#* ]] && continue
        
        echo -e "${GREEN}[*] Processing target: $target${NC}"
        if [[ "$target" == *"/"* ]]; then
            ping_sweep "$target"
            while IFS= read -r host; do
                scan_ports "$host"
            done < "$OUTPUT_DIR/live_hosts.txt"
        else
            # Single host
            scan_ports "$target"
        fi
    done < "$TARGETS_FILE"
    
    echo ""
    echo -e "${GREEN}[+] Scan completed. Results saved in $OUTPUT_DIR/${NC}"
    
    # Display summary
    if [ -f "$OUTPUT_DIR/vulnerabilities.txt" ]; then
        echo -e "${RED}[!] Vulnerabilities found:${NC}"
        cat "$OUTPUT_DIR/vulnerabilities.txt"
    else
        echo -e "${GREEN}[+] No vulnerabilities found${NC}"
    fi
}

# Run main function
main