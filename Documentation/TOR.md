# Tor Browser Setup and Usage Guide

## What is Tor?

**Tor (The Onion Router)** is free, open-source software that enables anonymous communication by routing your internet traffic through a network of volunteer-operated servers (relays). This makes it extremely difficult to trace your online activity back to you.

### Key Features

- **Anonymity**: Hides your IP address and location
- **Privacy**: Prevents websites from tracking you
- **Censorship Circumvention**: Access blocked websites
- **Free & Open Source**: No cost, auditable code
- **Multi-layer Encryption**: Traffic encrypted through multiple relays

---

## Installation

### Windows, Mac, or Linux

1. **Download Tor Browser**
   - Go to [torproject.org](https://www.torproject.org)
   - Click "Download Tor Browser"
   - Choose your operating system
   - **Important**: Only download from the official site

2. **Install**
   - **Windows**: Run the `.exe` file
   - **Mac**: Open the `.dmg` file and drag to Applications
   - **Linux**: Extract the archive and run `./start-tor-browser.desktop`

3. **Verify Installation** (Optional but Recommended)
   - Download the signature file
   - Verify using GPG to ensure authenticity

### Mobile (Android)

1. Download **Tor Browser** from Google Play Store or F-Droid
2. Install and launch the app

**Note**: iOS does not have an official Tor Browser. Use **Onion Browser** as an alternative (less secure).

---

## First-Time Setup

### 1. Launch Tor Browser

- Open the Tor Browser application
- You'll see the Tor connection screen

### 2. Connect to Tor Network

**Option A: Direct Connection (Most Users)**
- Click **"Connect"**
- Wait 10-30 seconds for connection to establish
- You'll see "Connected to Tor" when ready

**Option B: Configure Connection (If Blocked/Censored)**
- Click **"Configure Connection"**
- If Tor is blocked in your country, select **"Tor is censored in my country"**
- Choose a bridge type (obfs4 recommended)
- Click **"Connect"**

### 3. Security Level

After connecting, set your security level:

- Click the **shield icon** (top-right)
- Choose security level:
  - **Standard**: Normal browsing (default)
  - **Safer**: Disables some features that could be dangerous
  - **Safest**: Maximum security, disables JavaScript and more

**Recommendation**: Start with "Safer" for most users

---

## Basic Usage

### Browsing the Web

- Use Tor Browser like any other browser
- Search with **DuckDuckGo** (default, privacy-focused)
- Visit regular websites (.com, .org) or .onion sites
- Your traffic is automatically routed through Tor

### Understanding the Circuit

- Click the **lock icon** in address bar
- Select **"Connection details"** → **"Tor circuit for this site"**
- See the 3 relays your traffic routes through
- Click **"New Circuit for this Site"** to change route

### .onion Websites

- Special websites only accessible via Tor
- Examples: 
  - DuckDuckGo: `https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion`
  - The Tor Project: `http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion`
- More secure and anonymous than regular sites

---

## Security Best Practices

### DO:

✅ **Keep Tor Browser Updated**
   - Check for updates regularly
   - Updates include critical security patches

✅ **Use HTTPS Websites**
   - Look for the padlock icon
   - HTTPS Everywhere is built-in

✅ **Use Strong Passwords**
   - Even with Tor, use unique passwords
   - Consider a password manager

✅ **Maximize Browser Window**
   - Don't resize the window (helps prevent fingerprinting)
   - Or use full-screen mode

✅ **Create New Identity When Needed**
   - Click the **broom icon** (top-right)
   - Select "New Identity" to start fresh

### DON'T:

❌ **Don't Install Browser Extensions**
   - Can compromise anonymity
   - Use only what's pre-installed

❌ **Don't Torrent Over Tor**
   - Slows the network
   - Can leak your real IP address

❌ **Don't Use Google/Login to Accounts**
   - Google tracks heavily
   - Logging in links activity to your identity

❌ **Don't Open Downloaded Files While Online**
   - Can connect outside Tor
   - Open after disconnecting or in offline mode

❌ **Don't Use Tor with VPN (Usually)**
   - Can reduce anonymity
   - Only necessary in specific censorship cases

❌ **Don't Use Full Screen (Unless Maximized)**
   - Can reveal screen size for fingerprinting
   - Maximize window instead

---

## Common Issues & Solutions

### Tor Won't Connect

**Problem**: Connection fails or takes too long

**Solutions**:
1. Check your internet connection
2. Try "Configure Connection" → Use bridges
3. Disable firewall/antivirus temporarily
4. Try a different bridge type (obfs4, Snowflake)

### Slow Browsing Speed

**Problem**: Websites load very slowly

**Explanation**: This is normal! Traffic routes through 3+ relays worldwide.

**Solutions**:
1. Be patient - it's the cost of anonymity
2. Use "New Circuit" for stuck sites
3. Lower security level if acceptable
4. Avoid bandwidth-heavy activities (video streaming)

### Website Blocks Tor

**Problem**: Sites show CAPTCHA or block access

**Solutions**:
1. Use "New Identity" for fresh circuit
2. Try different exit node (new circuit)
3. Some sites actively block Tor - this is expected
4. Find alternative sources for the information

### CAPTCHA Everywhere

**Problem**: Constant CAPTCHA challenges

**Explanation**: Many sites see Tor traffic as suspicious

**Solutions**:
1. Complete the CAPTCHAs (annoying but necessary)
2. Try "New Identity" for better exit node
3. Use .onion versions of sites when available

---

## Advanced Features

### Bridges (For Censored Networks)

- **What**: Entry relays not publicly listed
- **When**: If Tor is blocked in your country
- **How**: Configure → "Tor is censored" → Select bridge type
- **Types**:
  - **obfs4**: Most common, good obfuscation
  - **Snowflake**: Uses volunteer proxies, good for heavy censorship
  - **meek**: Uses cloud services, slower but very effective

### Onion Services

- Websites ending in `.onion`
- Only accessible via Tor
- Both client and server are anonymous
- More secure than regular websites

### Security Slider

**Location**: Shield icon → Change Security Settings

**Levels**:
1. **Standard**: All features enabled
2. **Safer**: Disables JavaScript on non-HTTPS, some fonts, and media
3. **Safest**: JavaScript disabled everywhere, many features blocked

**Trade-off**: Higher security = less functionality

---

## Checking Your Connection

### Verify You're Using Tor

1. Visit: [check.torproject.org](https://check.torproject.org)
2. Should say: "Congratulations. This browser is configured to use Tor."
3. Shows your current Tor exit node IP

### Check for IP Leaks

1. Visit: [ipleak.net](https://ipleak.net)
2. Verify IP is not your real IP
3. Check for DNS leaks (should show Tor exit node)

---

## When to Use Tor

### Good Use Cases:

✅ Anonymous research
✅ Protecting privacy from surveillance
✅ Accessing blocked content in censored countries
✅ Whistleblowing or sensitive communications
✅ General privacy-conscious browsing
✅ Accessing .onion services

### Not Ideal For:

❌ Banking or financial transactions (many banks block Tor)
❌ Streaming video (too slow)
❌ Large file downloads (slow, burdens network)
❌ Sites requiring login (reduces anonymity)
❌ Torrenting (can leak IP)

---

## Additional Resources

- **Official Documentation**: [tb-manual.torproject.org](https://tb-manual.torproject.org)
- **Support**: [support.torproject.org](https://support.torproject.org)
- **Community**: Reddit r/TOR, Tor Project forums
- **Security Tips**: [tor.stackexchange.com](https://tor.stackexchange.com)

---

## Important Reminders

⚠️ **Tor is not magic**: It provides anonymity, not complete security
⚠️ **Behavior matters**: Poor operational security can compromise anonymity
⚠️ **Stay updated**: Always use the latest Tor Browser version
⚠️ **Legal considerations**: Know your local laws regarding Tor usage
⚠️ **Combine with good practices**: Use HTTPS, strong passwords, and common sense

---

**Remember**: Tor protects your *anonymity* (who you are), but you must still protect your *security* (what you do) through careful behavior online.
