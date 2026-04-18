"""
=============================================================================
  MITM ATTACK DETECTION ENGINE
  Real-time network anomaly detection for Man-in-the-Middle attacks
  Detects: ARP Spoofing | Certificate Changes | Latency Anomalies
=============================================================================
"""

import time
import hashlib
import threading
from datetime import datetime
from collections import defaultdict
from queue import Queue


# ═══════════════════════════════════════════════════════════════════════════
#  DETECTION EVENT
# ═══════════════════════════════════════════════════════════════════════════
class DetectionEvent:
    """Represents a single detection event raised by any detector module."""

    SEVERITY_LOW = "LOW"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_CRITICAL = "CRITICAL"

    def __init__(self, event_type, severity, source_ip, description, details=None):
        self.timestamp = datetime.now()
        self.event_type = event_type          # "ARP_SPOOF", "CERT_CHANGE", "LATENCY_SPIKE"
        self.severity = severity
        self.source_ip = source_ip
        self.description = description
        self.details = details or {}
        self.id = hashlib.md5(
            f"{self.timestamp}{self.event_type}{self.source_ip}".encode()
        ).hexdigest()[:12]

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": self.event_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "description": self.description,
            "details": self.details,
        }

    def __repr__(self):
        return f"[{self.severity}] {self.event_type} from {self.source_ip}: {self.description}"


# ═══════════════════════════════════════════════════════════════════════════
#  ARP SPOOFING DETECTOR
# ═══════════════════════════════════════════════════════════════════════════
class ARPSpoofDetector:
    """
    Monitors ARP reply packets and maintains an IP→MAC mapping table.
    Flags any IP that suddenly appears with a different MAC address.
    """

    def __init__(self, event_queue):
        self.event_queue = event_queue
        self.ip_mac_table = {}       # {ip: mac}
        self.spoof_count = defaultdict(int)
        self.packets_analyzed = 0
        self.lock = threading.Lock()

    def analyze(self, ip, mac, op=2):
        """Analyze an ARP reply. op=2 means ARP Reply (is-at)."""
        if op != 2:
            return None

        self.packets_analyzed += 1
        result = None

        with self.lock:
            if ip in self.ip_mac_table:
                known_mac = self.ip_mac_table[ip]
                if known_mac != mac:
                    self.spoof_count[ip] += 1

                    event = DetectionEvent(
                        event_type="ARP_SPOOF",
                        severity=DetectionEvent.SEVERITY_CRITICAL,
                        source_ip=ip,
                        description=f"ARP Spoofing detected! IP {ip} changed MAC from {known_mac} to {mac}",
                        details={
                            "legitimate_mac": known_mac,
                            "spoofed_mac": mac,
                            "spoof_count": self.spoof_count[ip],
                            "action": "BLOCK",
                        }
                    )
                    self.event_queue.put(event)
                    result = event
            else:
                self.ip_mac_table[ip] = mac
                result = "learned"

        return result

    def get_mappings(self):
        """Return a copy of the current IP→MAC table."""
        with self.lock:
            return dict(self.ip_mac_table)

    def get_stats(self):
        return {
            "packets_analyzed": self.packets_analyzed,
            "known_hosts": len(self.ip_mac_table),
            "spoofs_detected": sum(self.spoof_count.values()),
        }


# ═══════════════════════════════════════════════════════════════════════════
#  CERTIFICATE CHANGE DETECTOR
# ═══════════════════════════════════════════════════════════════════════════
class CertificateChangeDetector:
    """
    Tracks TLS certificate fingerprints per domain.
    An unexpected certificate change may indicate SSL stripping or
    an interception proxy injecting its own certificate.
    """

    def __init__(self, event_queue):
        self.event_queue = event_queue
        self.cert_store = {}         # {domain: {"fingerprint": ..., "issuer": ..., "first_seen": ...}}
        self.change_count = defaultdict(int)
        self.certs_analyzed = 0
        self.lock = threading.Lock()

    def analyze(self, domain, fingerprint, issuer="Unknown", ip="0.0.0.0"):
        """Analyze a certificate observed for a domain."""
        self.certs_analyzed += 1
        result = None

        with self.lock:
            if domain in self.cert_store:
                stored = self.cert_store[domain]
                if stored["fingerprint"] != fingerprint:
                    self.change_count[domain] += 1

                    severity = DetectionEvent.SEVERITY_HIGH
                    if stored["issuer"] != issuer:
                        severity = DetectionEvent.SEVERITY_CRITICAL

                    event = DetectionEvent(
                        event_type="CERT_CHANGE",
                        severity=severity,
                        source_ip=ip,
                        description=f"Certificate change detected for {domain}!",
                        details={
                            "domain": domain,
                            "original_fingerprint": stored["fingerprint"],
                            "new_fingerprint": fingerprint,
                            "original_issuer": stored["issuer"],
                            "new_issuer": issuer,
                            "change_count": self.change_count[domain],
                            "action": "ALERT",
                        }
                    )
                    self.event_queue.put(event)
                    result = event
            else:
                self.cert_store[domain] = {
                    "fingerprint": fingerprint,
                    "issuer": issuer,
                    "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": ip,
                }
                result = "stored"

        return result

    def get_store(self):
        with self.lock:
            return dict(self.cert_store)

    def get_stats(self):
        return {
            "certs_analyzed": self.certs_analyzed,
            "domains_tracked": len(self.cert_store),
            "cert_changes_detected": sum(self.change_count.values()),
        }


# ═══════════════════════════════════════════════════════════════════════════
#  LATENCY ANOMALY DETECTOR
# ═══════════════════════════════════════════════════════════════════════════
class LatencyAnomalyDetector:
    """
    Tracks baseline RTT (Round-Trip Time) to known hosts.
    A sudden latency spike indicates traffic may be rerouted through an
    attacker node, adding propagation delay.
    """

    SPIKE_THRESHOLD_MULTIPLIER = 3.0   # 3x the baseline = anomaly
    MIN_SAMPLES_FOR_BASELINE = 3

    def __init__(self, event_queue):
        self.event_queue = event_queue
        self.latency_history = defaultdict(list)   # {ip: [rtt_ms, ...]}
        self.baselines = {}                         # {ip: avg_rtt_ms}
        self.anomaly_count = defaultdict(int)
        self.measurements = 0
        self.lock = threading.Lock()

    def analyze(self, ip, rtt_ms):
        """Analyze a latency measurement to a host."""
        self.measurements += 1
        result = None

        with self.lock:
            self.latency_history[ip].append(rtt_ms)

            # Need enough samples to establish a baseline
            history = self.latency_history[ip]

            if len(history) >= self.MIN_SAMPLES_FOR_BASELINE:
                # Baseline = average of all but the latest measurement
                baseline_samples = history[:-1]
                baseline = sum(baseline_samples) / len(baseline_samples)
                self.baselines[ip] = baseline

                if rtt_ms > baseline * self.SPIKE_THRESHOLD_MULTIPLIER:
                    self.anomaly_count[ip] += 1

                    event = DetectionEvent(
                        event_type="LATENCY_SPIKE",
                        severity=DetectionEvent.SEVERITY_MEDIUM,
                        source_ip=ip,
                        description=f"Latency spike to {ip}: {rtt_ms:.1f}ms (baseline: {baseline:.1f}ms)",
                        details={
                            "current_rtt_ms": round(rtt_ms, 2),
                            "baseline_rtt_ms": round(baseline, 2),
                            "spike_ratio": round(rtt_ms / baseline, 2),
                            "threshold_multiplier": self.SPIKE_THRESHOLD_MULTIPLIER,
                            "anomaly_count": self.anomaly_count[ip],
                            "action": "MONITOR",
                        }
                    )
                    self.event_queue.put(event)
                    result = event

            if result is None:
                result = "recorded"

        return result

    def get_baselines(self):
        with self.lock:
            return dict(self.baselines)

    def get_history(self, ip=None):
        with self.lock:
            if ip:
                return list(self.latency_history.get(ip, []))
            return {k: list(v) for k, v in self.latency_history.items()}

    def get_stats(self):
        return {
            "measurements": self.measurements,
            "hosts_tracked": len(self.latency_history),
            "anomalies_detected": sum(self.anomaly_count.values()),
        }


# ═══════════════════════════════════════════════════════════════════════════
#  UNIFIED DETECTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════
class MITMDetectionEngine:
    """
    Unified engine that orchestrates all three detector modules
    and provides a single interface for the rest of the system.
    """

    def __init__(self):
        self.event_queue = Queue()
        self.arp_detector = ARPSpoofDetector(self.event_queue)
        self.cert_detector = CertificateChangeDetector(self.event_queue)
        self.latency_detector = LatencyAnomalyDetector(self.event_queue)
        self.all_events = []
        self._running = False

    def get_all_stats(self):
        """Aggregate statistics from all detectors."""
        arp = self.arp_detector.get_stats()
        cert = self.cert_detector.get_stats()
        lat = self.latency_detector.get_stats()

        return {
            "arp": arp,
            "cert": cert,
            "latency": lat,
            "total_attacks_detected": (
                arp["spoofs_detected"]
                + cert["cert_changes_detected"]
                + lat["anomalies_detected"]
            ),
            "total_events": len(self.all_events),
        }

    def get_recent_events(self, n=50):
        """Return the n most recent events as dicts."""
        return [e.to_dict() for e in self.all_events[-n:]]

    def drain_events(self):
        """Move events from queue to the event list. Returns new events."""
        new_events = []
        while not self.event_queue.empty():
            try:
                event = self.event_queue.get_nowait()
                self.all_events.append(event)
                new_events.append(event)
            except Exception:
                break
        return new_events
