# Seeker: Browser Geolocation Abuse, Privacy & Detection

_Upstream repository reviewed: 2026-11-21. No location collection or live deployment performed._

> [!CAUTION]
> **Defensive research & consent only.** The Seeker project uses social engineering and imitation web pages to induce browser geolocation permission. Never trick a person into sharing their location or expose coordinates, IP addresses or device fingerprints. See [Legal Notice](../LEGAL.md).

## What Seeker Demonstrates

[Seeker](https://github.com/thewhiteh4t/seeker) is a proof-of-concept for eliciting browser location permission on deceptive pages. Its upstream README discusses geolocation fields and device/browser metadata. The relevant issue is **consent and origin trust**, not a universal ability to locate devices secretly.

The browser Geolocation API normally requires a secure context and user permission. Location accuracy varies widely with device capabilities, sensors, Wi-Fi positioning, browser settings and permission state. An IP geolocation estimate is **not equivalent to GPS coordinates**, and neither guarantees a person's precise position.

## Data & Exposure Model

| Data Type | Privacy Concern | Validation / Caveat |
|---|---|---|
| Latitude & longitude | Potentially sensitive precise location | Permission normally required; accuracy varies |
| Accuracy radius | Indicates uncertainty around a coordinate | Not a guarantee of actual distance/error |
| Altitude, speed, heading | Additional motion context | Often unavailable or inaccurate |
| Public IP | Network/ISP metadata | May be VPN, CGNAT or shared address |
| Browser/device fingerprint hints | Cross-session tracking risk | Claims about uniqueness may be overstated |

## Defensive Lab: Inspect Permissions Without Requesting Location

A harmless local exercise can illustrate browser controls without obtaining coordinates:

1. Open the browser's site-permission settings and identify whether location access is blocked, prompted or allowed.
2. In the browser console of a **self-controlled local test page**, inspect permission state without calling `getCurrentPosition()`.
3. Observe whether your browser permits one-time grants, persistent grants or revocation; document exact browser/OS version.
4. Revoke any test permission. Do not record actual coordinates or share the page publicly.

```javascript
// Read-only illustration in the console of a page you control.
// Browser support for the Permissions API varies.
navigator.permissions.query({ name: "geolocation" })
  .then(result => console.log("Location permission state:", result.state))
  .catch(() => console.log("Permission state unavailable in this browser"));
```

This query does not request a position. Browser permission states can differ from OS-level location controls or permissions inherited from an existing origin.

## Recognizing a Suspicious Location Prompt

- A link in an unsolicited message leads to a page unrelated to a legitimate location service.
- A page demands location access as a precondition for unrelated content.
- Branding, hostname, app context or redirects do not match the expected service.
- Permission wording comes from the browser, but the **requesting origin** may still be deceptive.

A permission prompt is not automatically malicious. Evaluate whether the request is necessary, whether the site identity is expected and whether location is optional.

## Incident & Privacy Response

If someone unintentionally granted access, revoke the site's permission, close the page, review browser site data and notify the appropriate security/privacy team. For organizational incidents, preserve URLs, logs and timestamps **without retaining unnecessary precise-location data**. Browser history or DNS queries may show page access but do not by themselves prove that coordinates were sent.

## Detection, Training & Hardening

| Control | Practical Application |
|---|---|
| Browser permissions policy | Block location for sites that do not need it |
| Endpoint/browser management | Restrict geolocation access for untrusted origins where supported |
| Safe browsing & DNS filtering | Reduce known social-engineering entry points |
| Privacy-focused training | Teach origin checking and how to revoke permissions |
| Incident logging | Preserve relevant navigation/IdP/network events, minimize location retention |

Avoid relying on a fixed geolocation accuracy figure or claiming that any site can obtain GPS coordinates silently; user permission and environment matter.

## Related Guides & Sources

- [OPSEC & Privacy](../OPSEC/README.md) — privacy and operational safeguards
- [Device & Mobile Protection](../OPSEC/press-freedom/device-network-protection.md)
- [Phishing Investigation SOP](../PlayBooks/sop_phishing_analysis.md)
- [Seeker Upstream](https://github.com/thewhiteh4t/seeker) — threat-model source
- [MDN Geolocation API](https://developer.mozilla.org/en-US/docs/Web/API/Geolocation_API) & [Permissions API](https://developer.mozilla.org/en-US/docs/Web/API/Permissions_API)

---

[Tradecraft Index](./README.md) | [Start Here](../START_HERE.md) | [Legal Notice](../LEGAL.md)
