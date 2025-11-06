# Mullvad VPN Security Guide

## Why Mullvad is Excellent

**Mullvad** is one of the best VPNs for privacy and security:

✅ No logging policy  
✅ No personal info required (account is just a number)  
✅ Anonymous payment options (cash, crypto)  
✅ Owned/audited infrastructure  
✅ Open-source clients  

Since you already have Mullvad, you're in great shape. Here's how to maximize your security:

---

## Additional Security Layers

### 1. DNS Security (prevent leaks)

- Use Mullvad's DNS servers in their app settings
- Or use encrypted DNS: NextDNS or Cloudflare 1.1.1.1
- Test for leaks: [dnsleaktest.com](https://dnsleaktest.com)

### 2. Browser Hardening

- Use Firefox or Brave (better privacy than Chrome)
- Install: uBlock Origin, HTTPS Everywhere
- Disable WebRTC (can leak real IP)

### 3. Enable Kill Switch

- In Mullvad settings, enable "Always require VPN"
- Blocks all traffic if VPN disconnects

### 4. Split Tunneling (if needed)

- Some work apps may need direct connection
- Mullvad allows excluding specific apps

### 5. Multi-hop (extra paranoid)

- Mullvad supports multi-hop connections
- Routes through 2+ servers for extra anonymity

---

## For Work Specifically

- Keep work and personal browsing separate (different browsers/profiles)
- Use Mullvad's obfuscation if on restricted networks
- Consider compartmentalizing with VMs if handling sensitive data
