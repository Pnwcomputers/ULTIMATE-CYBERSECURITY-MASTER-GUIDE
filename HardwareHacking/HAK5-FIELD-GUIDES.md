# Hak5 Hardware Assessment Guides

These guides focus on consent-based testing, lab reproducibility, detection, and client reporting.

| Device | Field guide | Core assessment |
|---|---|---|
| Bash Bunny | [Bash Bunny Field Guide](./hak5-bash-bunny-field-guide.md) | USB composite-device controls, HID visibility, USB networking and storage policy |
| USB Rubber Ducky | [USB Rubber Ducky Field Guide](./hak5-usb-rubber-ducky-field-guide.md) | DuckyScript fundamentals, harmless HID markers, device-control and physical security drills |
| WiFi Pineapple Mark VII | [WiFi Pineapple Mark VII Field Guide](./hak5-wifi-pineapple-mark-vii-field-guide.md) | Passive AP inventory, encryption posture, rogue AP detection and WIDS/SIEM validation |

## Shared Assessment Workflow
1. Confirm written authorization, target inventory, operating window and safety stop conditions.
2. Verify firmware and document the exact hardware generation.
3. Run a synthetic test in a disposable lab before the client assessment.
4. Collect evidence of both expected and actual behavior, including negative results.
5. Restore configuration, remove test artifacts and deliver findings with remediation and retest criteria.

Related: [Hardware Hacking](./README.md) · [Assessment Blueprint](../PlayBooks/assessment-service-integration-map.md) · [Endpoint Visibility](../IncidentResponse/Endpoint-Visibility/README.md) · [Wireless Surveys](../Wardriving/README.md).
