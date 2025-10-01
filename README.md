# Basic Network Reconnaissance Scanner
A simple Bash script for network reconnaissance and vulnerability identification.

## Features
- Network discovery (ping sweep)
- Port scanning (common ports)
- Service identification
- Vulnerability checks:
  - Default SSH credentials
  - Anonymous FTP access
  - Default web pages
  - Directory listing detection

## Requirements
- Linux system with:
  - nmap
  - netcat (nc)
  - curl
  - sshpass
  - bash

## Usage
1. Install required tools:
   ```bash
   sudo apt-get install nmap netcat curl sshpass