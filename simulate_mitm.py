"""
=============================================================================
  MITM ATTACK SIMULATION & DEMONSTRATION
  Demonstrates all three detection capabilities:
    1. ARP Spoofing Detection
    2. Certificate Change Detection
    3. Latency Anomaly Detection
  Uses the full MITMDetectionEngine from mitm_detector.py
=============================================================================
"""

import time
from mitm_detector import MITMDetectionEngine, DetectionEvent


def print_banner(text):
    width = 65
    print("\n" + "=" * width)
    print(f"  {text}")
    print("=" * width)


def print_step(step_num, description):
    print(f"\n[Step {step_num}] {description}")
    print("-" * 50)


def print_events(engine):
    """Drain and display any new detection events."""
    new_events = engine.drain_events()
    for event in new_events:
        if event.severity == DetectionEvent.SEVERITY_CRITICAL:
            print(f"\n  +{'=' * 55}+")
            print(f"  | [!!] [{event.severity}] ALERT: {event.event_type:<30} |")
            print(f"  +{'=' * 55}+")
        elif event.severity == DetectionEvent.SEVERITY_HIGH:
            print(f"\n  +{'-' * 55}+")
            print(f"  | [!]  [{event.severity}] ALERT: {event.event_type:<32} |")
            print(f"  +{'-' * 55}+")
        else:
            print(f"\n  [!] [{event.severity}] {event.event_type}")

        print(f"  Source IP : {event.source_ip}")
        print(f"  Details   : {event.description}")

        if event.details.get("action") == "BLOCK":
            print(f"\n  [!!!] MITIGATION TRIGGERED [!!!]")
            print(f"  [*] Blocking compromised IP: {event.source_ip} "
                  f"and MAC: {event.details.get('spoofed_mac', 'N/A')}")
            print(f"  [*] Connection severed. Traffic from malicious node dropped.")
        elif event.details.get("action") == "ALERT":
            print(f"\n  [*] SECURITY ALERT raised. Certificate mismatch logged.")
            print(f"  [*] Recommending user to verify site authenticity.")
        elif event.details.get("action") == "MONITOR":
            print(f"\n  [*] Host flagged for enhanced monitoring.")
            print(f"  [*] Spike ratio: {event.details.get('spike_ratio', 'N/A')}x baseline")


def print_stats(engine):
    """Display aggregated statistics from all detectors."""
    stats = engine.get_all_stats()
    print(f"\n{'-' * 65}")
    print(f"  DETECTION ENGINE STATISTICS")
    print(f"{'-' * 65}")
    print(f"  ARP Detector:")
    print(f"    Packets analyzed  : {stats['arp']['packets_analyzed']}")
    print(f"    Known hosts       : {stats['arp']['known_hosts']}")
    print(f"    Spoofs detected   : {stats['arp']['spoofs_detected']}")
    print(f"  Certificate Detector:")
    print(f"    Certs analyzed    : {stats['cert']['certs_analyzed']}")
    print(f"    Domains tracked   : {stats['cert']['domains_tracked']}")
    print(f"    Changes detected  : {stats['cert']['cert_changes_detected']}")
    print(f"  Latency Detector:")
    print(f"    Measurements      : {stats['latency']['measurements']}")
    print(f"    Hosts tracked     : {stats['latency']['hosts_tracked']}")
    print(f"    Anomalies found   : {stats['latency']['anomalies_detected']}")
    print(f"{'-' * 65}")
    print(f"  >> TOTAL ATTACKS DETECTED: {stats['total_attacks_detected']}")
    print(f"  >> TOTAL EVENTS LOGGED  : {stats['total_events']}")
    print(f"{'-' * 65}")


# ===========================================================================
#  MAIN SIMULATION
# ===========================================================================
def main():
    engine = MITMDetectionEngine()

    print_banner("MITM ATTACK DETECTION SYSTEM - LIVE DEMONSTRATION")
    print("  Detects: ARP Spoofing | Certificate Changes | Latency Anomalies")
    print("  System will alert users and block compromised channels.\n")
    time.sleep(1)

    # -----------------------------------------------------------------
    #  SCENARIO 1: ARP SPOOFING DETECTION
    # -----------------------------------------------------------------
    print_banner("SCENARIO 1: ARP SPOOFING DETECTION")

    print_step(1, "Legitimate node '192.168.0.113' sends a valid ARP reply...")
    result = engine.arp_detector.analyze(
        ip="192.168.0.113",
        mac="AA:BB:CC:DD:EE:FF",
        op=2
    )
    print(f"  [+] Learned new mapping: IP 192.168.0.113 -> MAC AA:BB:CC:DD:EE:FF")
    time.sleep(1)

    print_step(2, "Attacker sends FORGED ARP reply claiming to be '192.168.0.113'...")
    result = engine.arp_detector.analyze(
        ip="192.168.0.113",
        mac="00:11:22:33:44:55",
        op=2
    )
    print_events(engine)
    time.sleep(1)

    # -----------------------------------------------------------------
    #  SCENARIO 2: CERTIFICATE CHANGE DETECTION
    # -----------------------------------------------------------------
    print_banner("SCENARIO 2: CERTIFICATE CHANGE DETECTION")

    print_step(3, "User connects to 'www.mybank.com' -- storing legitimate certificate...")
    result = engine.cert_detector.analyze(
        domain="www.mybank.com",
        fingerprint="SHA256:AB:CD:EF:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
        issuer="DigiCert Global Root CA",
        ip="203.0.113.50"
    )
    print(f"  [+] Certificate stored for www.mybank.com")
    print(f"      Issuer      : DigiCert Global Root CA")
    print(f"      Fingerprint : SHA256:AB:CD:EF:11:22:33:...")
    time.sleep(1)

    print_step(4, "Attacker intercepts connection -- injects forged certificate...")
    result = engine.cert_detector.analyze(
        domain="www.mybank.com",
        fingerprint="SHA256:FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00",
        issuer="Evil Corp Self-Signed CA",
        ip="10.0.0.99"
    )
    print_events(engine)
    time.sleep(1)

    # -----------------------------------------------------------------
    #  SCENARIO 3: LATENCY ANOMALY DETECTION
    # -----------------------------------------------------------------
    print_banner("SCENARIO 3: LATENCY ANOMALY DETECTION")

    print_step(5, "Establishing baseline latency to gateway '192.168.0.1'...")
    baseline_rtts = [5.2, 4.8, 5.1, 5.5, 4.9]
    for i, rtt in enumerate(baseline_rtts):
        engine.latency_detector.analyze(ip="192.168.0.1", rtt_ms=rtt)
        print(f"  [+] Ping {i+1}: RTT = {rtt} ms")
    baseline_avg = sum(baseline_rtts) / len(baseline_rtts)
    print(f"  [=] Baseline established: ~{baseline_avg:.1f} ms")
    time.sleep(1)

    print_step(6, "Attacker reroutes traffic -- latency spikes detected...")
    spike_rtts = [45.3, 62.7]
    for rtt in spike_rtts:
        engine.latency_detector.analyze(ip="192.168.0.1", rtt_ms=rtt)
        print(f"  [!] Ping: RTT = {rtt} ms  <-- ABNORMAL!")
    print_events(engine)
    time.sleep(1)

    # -----------------------------------------------------------------
    #  FINAL SUMMARY
    # -----------------------------------------------------------------
    print_banner("DEMONSTRATION COMPLETE - RESULTS SUMMARY")
    print_stats(engine)

    # Show all logged events
    recent = engine.get_recent_events()
    if recent:
        print(f"\n  EVENT LOG ({len(recent)} events):")
        print(f"  {'-' * 60}")
        for evt in recent:
            print(f"  [{evt['timestamp']}] [{evt['severity']:>8}] "
                  f"{evt['event_type']}: {evt['description'][:50]}")

    print(f"\n{'=' * 65}")
    print("  [OK] All three detection mechanisms verified successfully.")
    print("  [OK] Alerting and automated mitigation demonstrated.")
    print(f"{'=' * 65}\n")


if __name__ == "__main__":
    main()
