#!/bin/bash
# ============================================================
# demo_all.sh -- Four buffer-overflow vulnerability demos
# Run on a self-owned VM / loopback only.
#
#   bash demo_all.sh build      # compile all four servers
#   bash demo_all.sh hijack     # demo 1: control-flow hijack (port 9999)
#   bash demo_all.sh leak       # demo 2: read sensitive data (port 9998)
#   bash demo_all.sh integer    # demo 3: integer/length bug   (port 9997)
#   bash demo_all.sh dos        # demo 4: denial of service    (port 9996)
# ============================================================
CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'

build() {
  echo "[*] disabling ASLR (needed for demos 1 & 3 determinism)"
  echo 0 | sudo tee /proc/sys/kernel/randomize_va_space >/dev/null
  gcc -g -O0 -fno-stack-protector -no-pie server.c          -o server
  gcc -O0 -fno-stack-protector            leak_server.c     -o leak_server
  gcc -g -O0 -fno-stack-protector -no-pie integer_server.c  -o integer_server
  gcc -O0 -fno-stack-protector            dos_server.c      -o dos_server
  echo "[*] built: server, leak_server, integer_server, dos_server"
}

case "$1" in
  build) build ;;
  hijack)
    echo -e "${RED}[1] CONTROL-FLOW HIJACK (port 9999)${NC}"
    ./server >/dev/null 2>&1 & SRV=$!; sleep 1
    python3 exploit.py 127.0.0.1 9999
    kill $SRV 2>/dev/null ;;
  leak)
    echo -e "${RED}[2] SENSITIVE DATA DISCLOSURE (port 9998)${NC}"
    ./leak_server >/dev/null 2>&1 & SRV=$!; sleep 1
    echo "benign (short input):"
    python3 -c "import socket;s=socket.create_connection(('127.0.0.1',9998));s.sendall(b'hello');print(' ',s.recv(999).decode(errors='replace').strip())"
    echo "attack (32 bytes -> leak):"
    python3 leak_exploit.py 127.0.0.1 9998
    kill $SRV 2>/dev/null ;;
  integer)
    echo -e "${RED}[3] INTEGER/LENGTH BUG (port 9997)${NC}"
    ./integer_server >/dev/null 2>&1 & SRV=$!; sleep 1
    python3 integer_exploit.py 127.0.0.1 9997
    kill $SRV 2>/dev/null ;;
  dos)
    echo -e "${RED}[4] DENIAL OF SERVICE (port 9996)${NC}"
    ./dos_server >/dev/null 2>&1 & SRV=$!; sleep 1
    echo "benign client first:"
    python3 -c "import socket;s=socket.create_connection(('127.0.0.1',9996));s.sendall(b'hi');print(' ',s.recv(99))" 2>/dev/null
    python3 dos_exploit.py 127.0.0.1 9996
    kill $SRV 2>/dev/null ;;
  *) echo "Usage: bash demo_all.sh [build|hijack|leak|integer|dos]" ;;
esac
