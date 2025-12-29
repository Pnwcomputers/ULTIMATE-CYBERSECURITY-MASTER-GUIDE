# USB Rubber Ducky Script Compilation Guide

## Overview
These DuckyScript payloads are designed for the USB Rubber Ducky by Hak5. They must be compiled into `inject.bin` format before deployment.

## Compilation Methods

### Method 1: Hak5 Payload Studio (Recommended)
The easiest way to compile DuckyScript payloads.

1. **Visit**: https://payloadstudio.hak5.org/
2. **Paste** your `.txt` DuckyScript into the editor
3. **Select** your Ducky model:
   - USB Rubber Ducky (Original)
   - USB Rubber Ducky (2022+)
4. **Click** "Compile"
5. **Download** the `inject.bin` file

### Method 2: Hak5 Encoder (Command Line)
For offline compilation or automation.

**Installation:**
```bash
# Download from Hak5
wget https://github.com/hak5/usbrubberducky-payloads/raw/master/duckencoder.jar

# Or install via package manager (if available)
```

**Compile:**
```bash
java -jar duckencoder.jar -i payload.txt -o inject.bin
```

**Options:**
- `-i` : Input DuckyScript file (.txt)
- `-o` : Output compiled file (inject.bin)
- `-l` : Keyboard layout (default: US)

### Method 3: Duck Toolkit
Alternative online encoder.

1. **Visit**: https://ducktoolkit.com/encode
2. **Paste** your DuckyScript
3. **Select** keyboard layout
4. **Download** `inject.bin`

## Deployment

### USB Rubber Ducky Setup
1. **Insert** microSD card into your computer
2. **Copy** `inject.bin` to the **root** of the SD card
3. **Safely eject** the SD card
4. **Insert** SD card into USB Rubber Ducky
5. **Plug** Rubber Ducky into target system

### File Structure
```
/
├── inject.bin          # Your compiled payload (REQUIRED)
├── config.txt          # Optional configuration
└── switch.txt          # Multi-payload configuration (optional)
```

## Keyboard Layouts

DuckyScript supports multiple keyboard layouts. If your target system uses a non-US keyboard:

**Common Layouts:**
- `us` - US English (default)
- `uk` - UK English
- `de` - German
- `fr` - French
- `es` - Spanish
- `it` - Italian

**Specify in Payload Studio** or use encoder flag:
```bash
java -jar duckencoder.jar -i payload.txt -o inject.bin -l uk
```

## Testing & Debugging

### Test Environment
**Always test payloads in a controlled environment:**
- Virtual machine (VMware, VirtualBox)
- Test computer with no sensitive data
- Sandbox environment

### Common Issues

**Payload not executing:**
- ✓ Verify `inject.bin` is in SD card root
- ✓ Check SD card is properly formatted (FAT32)
- ✓ Ensure Ducky has power (LED should flash)

**Commands typing incorrectly:**
- ✓ Wrong keyboard layout selected
- ✓ Increase `DELAY` values if system is slow
- ✓ Check for special characters in script

**Payload timing out:**
- ✓ Increase initial `DELAY` (system boot time)
- ✓ Add more delays between commands
- ✓ Some systems need 3-5 seconds before Ducky is recognized

## Syntax Quick Reference
```duckyscript
REM Comment - not executed
DELAY 1000          # Wait 1000ms (1 second)
DEFAULTDELAY 100    # Set default delay between keystrokes

GUI r               # Windows + R
CTRL ALT DELETE     # Key combinations
ENTER               # Press Enter
STRING text here    # Type text

ALT F4              # Alt + F4
SHIFT a             # Shift + a (uppercase A)
```

## Best Practices

### 1. Add Delays Appropriately
- Initial delay: `DELAY 2000` minimum (system recognition)
- Between commands: `DELAY 500-1000` (execution time)
- After opening apps: `DELAY 2000-3000` (load time)
- Long operations: `DELAY 5000+` (searches, installs)

### 2. Error Handling
- Assume target system may be slower than expected
- Test on various system speeds
- Add conservative delays for production use

### 3. Documentation
- Include clear comments with `REM`
- Document target OS and version
- List prerequisites (admin rights, etc.)
- Note expected execution time

### 4. Version Control
```duckyscript
REM =============================================
REM Title: Payload Name
REM Author: Your Name
REM Version: 1.0
REM Target: Windows 10/11
REM Description: What this payload does
REM =============================================
```

## Security & Ethics

### ⚠️ IMPORTANT LEGAL NOTICE

**These tools are for AUTHORIZED use only:**
- ✓ Personal systems you own
- ✓ Systems you have written permission to test
- ✓ Professional penetration testing with contracts
- ✓ Educational environments with explicit authorization

**NEVER use on:**
- ✗ Systems you don't own
- ✗ Systems without explicit written permission
- ✗ Public computers
- ✗ Any system without authorization

**Unauthorized access to computer systems is illegal** under:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Similar laws in virtually all countries

### Professional Use
For legitimate IT/security work:
1. **Always obtain written authorization** before testing
2. **Document** all activities and findings
3. **Secure** payloads and results appropriately
4. **Follow** responsible disclosure practices

## Resources

- **Hak5 Forums**: https://forums.hak5.org/
- **Official Docs**: https://docs.hak5.org/usb-rubber-ducky/
- **Payload Library**: https://github.com/hak5/usbrubberducky-payloads
- **DuckyScript Docs**: https://docs.hak5.org/hak5-usb-rubber-ducky/duckyscript-tm-quick-reference

## Support

For issues or questions:
- Check Hak5 documentation first
- Search Hak5 forums for similar issues
- Review payload syntax carefully
- Test in VM before production use

## Contributing

When submitting payloads to this repository:
1. Test thoroughly on target OS
2. Include clear documentation
3. Follow naming conventions
4. Add comments explaining each section
5. List all requirements and dependencies

---

**Pacific NW Computers**  
Email: jon@pnwcomputers.com  
Phone: 360-624-7379

*Always use these tools ethically and legally.*
