Nmap Scanner Pretty (Go)

Overview

Nmap Scanner Pretty is a terminal-based Go program using nmap to scan hosts and ports, producing colorful, emoji-rich, and terminal-friendly outputs. Results are exported in XML, JSON, and a Log.txt file.

This tool is intended for educational, legal, and penetration testing practice only.

Features

Supports IP addresses, hostnames, URLs, and CIDR ranges.

Generates colored terminal output with emojis for open/closed/filtered ports.

Saves scan results as XML, JSON, and Log.txt.

Configurable nmap arguments, scan timeout, and output directory.

Compatible with Termux, Linux, macOS, and Windows.


Prerequisites

Go installed (version 1.21+ recommended)

nmap installed and available in PATH

Optional: clang if CGO is needed (or disable CGO for pure-Go build)


Installation Examples

Termux:

pkg update && pkg upgrade -y
pkg install golang git nmap clang -y
termux-setup-storage

Linux (Debian/Ubuntu):

sudo apt update && sudo apt install golang git nmap clang -y

macOS (Homebrew):

brew install go git nmap clang

Windows:

Install Go from https://go.dev/dl/

Install nmap from https://nmap.org/download.html

Optional: Install Git from https://git-scm.com/downloads


Setup & Build

1. Clone or copy project files.


2. Verify nmap installation: nmap --version


3. Build program:



# With clang
go build -o nmapscanner nmap_scanner.go

# Without CGO (no clang required)
CGO_ENABLED=0 go build -o nmapscanner nmap_scanner.go

Usage

# Scan targets
./nmapscanner -targets "192.168.1.1,example.com,https://example.com"

# Custom nmap arguments
./nmapscanner -targets "example.com" -nmap-args "-sV -p80,443 --open"

# Specify output directory
./nmapscanner -targets "example.com" -outdir ~/my_scans

Output

scan_TIMESTAMP.xml — Raw XML

scan_TIMESTAMP.json — JSON format

Log.txt — Pretty log with emojis


Notes

Only scan networks/hosts you own or have permission to scan.

Terminal output is colorful; file outputs include plain text with emojis.


License

MIT License — free to use for educational and legal purposes.


---

Made with 💙 by Matin

