"""Offline checks for the intentionally scoped conceptual SVG diagram batch.

No live sensor, SIEM, EDR, or hardware tests are attempted by this suite.
"""
from pathlib import Path
import re
import unittest
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]

DIAGRAM_GUIDES = {
    "assets/diagrams/purple-team-emulation-detection-loop.svg": (
        "PlayBooks/purple-team-detection-validation.md",
        "PlayBooks/PurpleTeam_Detailed.md",
    ),
    "assets/diagrams/detection-evidence-verification-gates.svg": (
        "IncidentResponse/SIEM/detection-content-validation.md",
        "Documentation/CANARY-DETECTION-VALIDATOR.md",
    ),
    "assets/diagrams/cyberdeck-policy-zones.svg": (
        "Cyberdeck/docs/ARCHITECTURE.md",
    ),
    "assets/diagrams/wireshark-capture-display-boundaries.svg": (
        "Documentation/wireshark.md",
    ),
    "assets/diagrams/ai-soc-trust-and-approval-boundaries.svg": (
        "AI/ai-security-operations-workflows.md",
    ),
    "assets/diagrams/cti-to-approved-emulation-gates.svg": (
        "PlayBooks/PurpleTeam_Detailed.md",
    ),
    "assets/diagrams/repository-evidence-gates.svg": (
        "Documentation/REPOSITORY-VERIFICATION-PROTOCOL.md",
    ),
    "assets/diagrams/osint-case-evidence-provenance.svg": (
        "OSINT/Playbook/README.md",
    ),
    "assets/diagrams/wardrive-go-platform-collection-boundaries.svg": (
        "Wardriving/wardrive-go.md",
    ),
    "assets/diagrams/cyberdeck-seven-stage-assessment-gates.svg": (
        "Cyberdeck/docs/ASSESSMENT_WORKFLOW.md",
    ),
    "assets/diagrams/mcp-trust-and-approval-boundaries.svg": (
        "AI/mcp-tooling-and-permissions.md",
    ),
    "assets/diagrams/wardriving-survey-data-privacy-gates.svg": (
        "Wardriving/data-handling.md",
    ),
    "assets/diagrams/cyberdeck-evidence-and-redaction-lifecycle.svg": (
        "Cyberdeck/docs/EVIDENCE_AND_PRIVACY.md",
    ),
    "assets/diagrams/ai-evaluation-evidence-matrix.svg": (
        "AI/ai-evaluation-and-regression-testing.md",
    ),
    "assets/diagrams/uconsole-hardware-os-preflight-paths.svg": (
        "uConsole/README.md",
    ),
    "assets/diagrams/cryptography-primitive-decision-map.svg": (
        "Cryptography/README.md",
    ),
    "assets/diagrams/homelab-passive-ids-visibility-mirror-tap.svg": (
        "Homelab/README.md",
    ),
    "assets/diagrams/firmware-flashing-verification-gates.svg": (
        "Documentation/firmware-web-flashers.md",
    ),
    "assets/diagrams/device-firmware-compatibility-selection.svg": (
        "Documentation/device-firmware-list.md",
    ),
    "assets/diagrams/cyberdeck-portable-device-roles-and-artifacts.svg": (
        "Cyberdeck/docs/PORTABLE_WIRELESS_FIELD_DEVICES.md",
    ),
    "assets/diagrams/homelab-virtual-network-isolation-paths.svg": (
        "Homelab/HomeLab_Setup.md",
    ),
    "assets/diagrams/ai-notes-hooks-evidence-boundaries.svg": (
        "AI/notes-hooks-and-automation.md",
    ),
    "assets/diagrams/ai-milestone-independent-acceptance-gate.svg": (
        "AI/milestones-and-acceptance-criteria.md",
    ),
    "assets/diagrams/osint-fraud-investigation-source-confidence.svg": (
        "OSINT/Playbook/investigation_guide.md",
    ),
    "assets/diagrams/wardriving-field-quality-acceptance.svg": (
        "Wardriving/field-workflow.md",
    ),
    "assets/diagrams/graylog-data-node-ingest-architecture.svg": (
        "IncidentResponse/SIEM/graylog.md",
    ),
    "assets/diagrams/live-response-volatility-evidence-gates.svg": (
        "IncidentResponse/Digital-Forensics/LiveData/live_data_collection.md",
    ),
    "assets/diagrams/honeypot-wazuh-telemetry-evidence-path.svg": (
        "IncidentResponse/HoneyPot/wazuh-honeypot-integration.md",
    ),
    "assets/diagrams/cdc-snapshot-offset-replay-boundary.svg": (
        "Data-Engineering/Phase2/streaming_cdc.md",
    ),
    "assets/diagrams/recovery-point-rpo-rto-replay-timeline.svg": (
        "Data-Engineering/Phase3/data_recovery_replay.md",
    ),
    "assets/diagrams/webapp-object-authorization-role-matrix.svg": (
        "WebAppSecurity/methodology.md",
    ),
    "assets/diagrams/proxmox-honeynet-vm-trust-boundaries.svg": (
        "IncidentResponse/HoneyPot/proxmox-vm-honeynet.md",
    ),
    "assets/diagrams/osquery-interactive-scheduled-siem-flow.svg": (
        "IncidentResponse/Endpoint-Visibility/Linux/osquery.md",
    ),
    "assets/diagrams/data-lineage-job-run-access-boundaries.svg": (
        "Data-Engineering/Phase3/data_governance_lineage.md",
    ),
    "assets/diagrams/rag-ingestion-retrieval-permission-boundaries.svg": (
        "AI/rag-and-knowledge-engineering.md",
    ),
    "assets/diagrams/ai-structured-output-authorized-action-gates.svg": (
        "AI/structured-outputs-and-data-contracts.md",
    ),
    "assets/diagrams/ai-agent-ambiguous-write-reconciliation.svg": (
        "AI/agent-reliability-and-recovery.md",
    ),
    "assets/diagrams/pipeline-observability-reconciliation-slo.svg": (
        "Data-Engineering/Phase3/pipeline_observability.md",
    ),
    "assets/diagrams/nanovna-s11-resonance-vs-match.svg": (
        "SDR/nanovna/05-antenna-tuning.md",
    ),
    "assets/diagrams/tpot-hive-sensor-management-boundaries.svg": (
        "IncidentResponse/HoneyPot/tpot.md",
    ),
    "assets/diagrams/tsurugi-osint-image-provenance-case-flow.svg": (
        "OSINT/TSURUGI_LINUX_OSINT_GUIDE.md",
    ),
    "assets/diagrams/splunk-forwarder-indexer-search-head-data-flow.svg": (
        "IncidentResponse/SIEM/splunk.md",
    ),
    "assets/diagrams/space-ground-command-telemetry-trust-boundaries.svg": (
        "SpaceSecurity/PartII.md",
    ),
    "assets/diagrams/nanovna-s11-s21-calibration-plane.svg": (
        "SDR/nanovna/03-calibration.md",
    ),
    "assets/diagrams/diy-http-honeypot-jsonl-wazuh-safe-path.svg": (
        "IncidentResponse/HoneyPot/diy-sensor-lab.md",
    ),
    "assets/diagrams/elastic-stack-log-ingest-index-search.svg": (
        "IncidentResponse/SIEM/elk_stack.md",
    ),
    "assets/diagrams/spaceflight-fsw-cfs-security-layers.svg": (
        "SpaceSecurity/PartIII.md",
    ),
    "assets/diagrams/userland-android-proot-capability-boundaries.svg": (
        "Mobile/UserLAnd/readme.md",
    ),
    "assets/diagrams/etl-vs-elt-transform-privacy-and-replay.svg": (
        "Data-Engineering/Phase1/etl_elt_pipeline_design.md",
    ),
    "assets/diagrams/ai-multi-agent-fanout-review-integration.svg": (
        "AI/multi-agent-orchestration.md",
    ),
    "assets/diagrams/ai-project-status-evidence-handoff-flow.svg": (
        "AI/agent-project-workflows.md",
    ),
    "assets/diagrams/data-orchestrator-interval-dependency-publish-gates.svg": (
        "Data-Engineering/Phase2/workflow_orchestration.md",
    ),
    "assets/diagrams/api-file-ingest-cursor-retry-reconciliation.svg": (
        "Data-Engineering/Phase2/api_file_ingestion.md",
    ),
    "assets/diagrams/wifi-deauth-disassoc-pmf-corroboration.svg": (
        "Documentation/wifi-deauthentication-detection.md",
    ),
    "assets/diagrams/ble-sniffle-advertising-connection-path.svg": (
        "Documentation/ble-capture-sniffle.md",
    ),
    "assets/diagrams/ad-kerberos-ticket-trust-recovery.svg": (
        "Checklists/ActiveDirectory.md",
    ),
    "assets/diagrams/android-app-static-runtime-backend-test-lanes.svg": (
        "Checklists/Android-Applications-Checklist.md",
    ),
    "assets/diagrams/social-osint-account-provenance-verification.svg": (
        "OSINT/OSINT_socialmedia.md",
    ),
    "assets/diagrams/uconsole-cm5-display-diagnostic-recovery.svg": (
        "uConsole/CM5-DISPLAY-RECOVERY.md",
    ),
    "assets/diagrams/network-detection-sensor-coverage-and-evidence.svg": (
        "Tradecraft/network-detection.md",
    ),
    "assets/diagrams/locksport-pin-tumbler-shear-line.svg": (
        "Documentation/Locksport.md",
    ),
    "assets/diagrams/wpa-pmkid-eapol-hc22000-protocol-boundaries.svg": (
        "Documentation/hcxtoolshashcat.md",
    ),
    "assets/diagrams/esp32-c5-wardriver-normal-node-core.svg": (
        "Wardriving/esp32-c5-wardriver.md",
    ),
    "assets/diagrams/hardware-bench-inventory-stress-storage-safety.svg": (
        "HardwareTesting/Manjaro_Intel_TestBench.md",
    ),
    "assets/diagrams/voip-sip-signaling-vs-rtp-media-security.svg": (
        "Checklists/voip-checklist.md",
    ),
    "assets/diagrams/linux-privilege-risk-and-vendor-patch-triage.svg": (
        "Checklists/Linux-Privilege-Escalation.md",
    ),
    "assets/diagrams/arduino-ide-board-port-bootloader-diagnostics.svg": (
        "Documentation/arduinoIDE.md",
    ),
    "assets/diagrams/osint-cti-source-quality-to-detection.svg": (
        "Tradecraft/osint-threat-intel.md",
    ),
    "assets/diagrams/ghidra-analysis-hypothesis-validation.svg": (
        "ReverseEngineering/ghidra-guide-index.md",
    ),
    "assets/diagrams/remnux-malware-analysis-network-isolation.svg": (
        "ReverseEngineering/remnux-malware-analysis-guide.md",
    ),
    "assets/diagrams/kismet-wardrive-gps-log-retention-flow.svg": (
        "Wardriving/kismet.md",
    ),
    "assets/diagrams/identity-alert-investigation-evidence-containment.svg": (
        "PlayBooks/unauth_access.md",
    ),
    "assets/diagrams/cyberdeck-zone-policy-logical-architecture.svg": (
        "Cyberdeck/README.md",
    ),
    "assets/diagrams/incident-response-nist-800-61r3-csf2-operations.svg": (
        "PlayBooks/BlueTeam_IncResp_Enhanced.md",
    ),
    "assets/diagrams/ai-audit-claims-tools-and-outcomes.svg": (
        "AI/verification-and-ai-audits.md",
    ),
    "assets/diagrams/classical-cipher-frequency-vigenere-ic-analysis.svg": (
        "Cryptography/Classical/cryptanalysis.md",
    ),
    "assets/diagrams/bash-script-input-validation-and-dry-run-gates.svg": (
        "Scripts/Bash/bash_scripting_cheat-sheet.md",
    ),
    "assets/diagrams/esp32-firmware-board-build-flash-acceptance.svg": (
        "Documentation/esp32-security-firmware-catalog.md",
    ),
    "assets/diagrams/ai-model-routing-policy.svg": (
        "AI/model-routing-and-cost-management.md",
    ),
    "assets/diagrams/openscad-preset-to-export.svg": (
        "CAD/OpenSCAD/02-project-structure.md",
    ),
    "CAD/OpenSCAD/images/openscad-shortcuts-cheatsheet.svg": (
        "CAD/OpenSCAD/06-keyboard-shortcuts.md",
    ),
    "assets/diagrams/vigenere-candidate-periods.svg": (
        "Cryptography/Classical/cryptanalysis.md",
    ),
    "assets/diagrams/volatility-evidence-triage.svg": (
        "IncidentResponse/Digital-Forensics/Memory/volatility_cheatsheet.md",
    ),
}


class VisualGuideTests(unittest.TestCase):
    def test_conceptual_svgs_are_well_formed_and_accessible(self):
        for path in DIAGRAM_GUIDES:
            with self.subTest(asset=path):
                asset = ROOT / path
                self.assertTrue(asset.is_file(), path)
                svg = ET.parse(asset).getroot()
                ns = "{http://www.w3.org/2000/svg}"
                self.assertEqual(svg.tag, ns + "svg")
                self.assertEqual(svg.get("role"), "img")
                self.assertEqual(svg.get("aria-labelledby"), "title desc")
                self.assertTrue((svg.find(ns + "title").text or "").strip())
                self.assertTrue((svg.find(ns + "desc").text or "").strip())
                text = asset.read_text(encoding="utf-8")
                self.assertNotIn("<script", text.lower())
                self.assertNotIn("<image", text.lower())

    def test_each_svg_is_embedded_in_expected_guide_and_index(self):
        index = (ROOT / "assets/README.md").read_text(encoding="utf-8")
        for path, guides in DIAGRAM_GUIDES.items():
            filename = Path(path).name
            with self.subTest(asset=path):
                self.assertIn(filename, index)
                for guide in guides:
                    md = (ROOT / guide).read_text(encoding="utf-8")
                    rel = __import__("os").path.relpath(ROOT / path, (ROOT / guide).parent)
                    target = re.escape(rel.replace("\\", "/"))
                    self.assertRegex(md, rf"!\[[^\]\n]+\]\((?:\./)?{target}\)")


if __name__ == "__main__":
    unittest.main()
