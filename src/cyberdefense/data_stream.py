"""
CyberDefense Data Ingestion & Stream Processing
===============================================
Combines log parsing, asynchronous stream playback, and synthetic telemetry generation
into a single, clean module.

Components:
  - LogParser: Universal parser transforming structured logs, standard Linux Syslog/Auth.log,
    sudo executions, and CSV (CICIDS-2017 style) into normalized LogEvent models.
  - LogMonitor: Asynchronous streaming engine and file replayer with configurable speeds,
    pause/resume controls, and progress tracking.
  - SyntheticLogGenerator: Enterprise-grade synthetic data generator producing realistic multi-stage
    cyber attacks and benign false-positive scenarios (internal backups, employee typos, scanner audits).
"""

import asyncio
from collections import deque
import csv
from datetime import datetime, timedelta
import json
import logging
from pathlib import Path
import random
import re
from typing import Any, Callable, Coroutine

from cyberdefense.models import LogEvent, EventType, Protocol

logger = logging.getLogger("cyberdefense.data_stream")


# ══════════════════════════════════════════════════════════════════
# 1. LOG PARSER (Universal Telemetry Ingestion)
# ══════════════════════════════════════════════════════════════════

# Format: 2026-10-23T01:15:00Z | AUTH_LOGIN | 192.168.1.105:54321 -> 10.0.0.5:22 | admin | FAILURE | 120 | Failed password attempt
STRUCTURED_RE = re.compile(
    r"^(?P<timestamp>[^|]+)\s*\|\s*(?P<event_type>[^|]+)\s*\|\s*(?P<src_ip>[^:]+):(?P<src_port>\d+)\s*->\s*(?P<dst_ip>[^:]+):(?P<dst_port>\d+)\s*\|\s*(?P<user>[^|]+)\s*\|\s*(?P<status>[^|]+)\s*\|\s*(?P<bytes>\d+)\s*\|\s*(?P<details>.*)$"
)

# Standard Linux Syslog auth.log formats
SYSLOG_AUTH_FAIL_RE = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<src_port>\d+)"
)

SYSLOG_AUTH_SUCC_RE = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Accepted\s+password\s+for\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<src_port>\d+)"
)

SYSLOG_SUDO_RE = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sudo:\s+(?P<user>\S+)\s*:\s+TTY=.*COMMAND=(?P<cmd>.*)"
)

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class LogParser:
    """Parses various text log formats into normalized LogEvent objects."""

    @staticmethod
    def parse_line(line: str) -> LogEvent | None:
        """Parse a single raw line into a LogEvent."""
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        # Try JSON format first
        if line.startswith("{") and line.endswith("}"):
            try:
                data = json.loads(line)
                return LogEvent(**data)
            except Exception:
                pass

        # 1. Structured pipe-separated format
        m = STRUCTURED_RE.match(line)
        if m:
            d = m.groupdict()
            try:
                ts = datetime.fromisoformat(d["timestamp"].replace("Z", "+00:00"))
            except Exception:
                ts = datetime.utcnow()

            event_type_str = d["event_type"].strip().upper()
            try:
                evt_type = EventType(event_type_str)
            except ValueError:
                evt_type = EventType.SYSTEM_EVENT

            return LogEvent(
                timestamp=ts,
                source_ip=d["src_ip"].strip(),
                source_port=int(d["src_port"]),
                dest_ip=d["dst_ip"].strip(),
                dest_port=int(d["dst_port"]),
                protocol=Protocol.TCP,
                event_type=evt_type,
                user=d["user"].strip(),
                status=d["status"].strip().upper(),
                bytes_transferred=int(d["bytes"]),
                details=d["details"].strip(),
                raw_line=line,
            )

        # 2. Linux Syslog SSH Auth failure
        m = SYSLOG_AUTH_FAIL_RE.search(line)
        if m:
            d = m.groupdict()
            return LogEvent(
                timestamp=datetime.utcnow(),
                source_ip=d["src_ip"],
                source_port=int(d["src_port"]),
                dest_ip="10.0.0.5",
                dest_port=22,
                protocol=Protocol.TCP,
                event_type=EventType.AUTH_LOGIN,
                user=d["user"],
                status="FAILURE",
                bytes_transferred=128,
                details=f"SSH failed password for {d['user']} from {d['src_ip']}",
                raw_line=line,
            )

        # 3. Linux Syslog SSH Auth success
        m = SYSLOG_AUTH_SUCC_RE.search(line)
        if m:
            d = m.groupdict()
            return LogEvent(
                timestamp=datetime.utcnow(),
                source_ip=d["src_ip"],
                source_port=int(d["src_port"]),
                dest_ip="10.0.0.5",
                dest_port=22,
                protocol=Protocol.TCP,
                event_type=EventType.AUTH_LOGIN,
                user=d["user"],
                status="SUCCESS",
                bytes_transferred=512,
                details=f"SSH accepted password for {d['user']} from {d['src_ip']}",
                raw_line=line,
            )

        # 4. Linux Syslog Sudo execution
        m = SYSLOG_SUDO_RE.search(line)
        if m:
            d = m.groupdict()
            return LogEvent(
                timestamp=datetime.utcnow(),
                source_ip="127.0.0.1",
                dest_ip="10.0.0.5",
                dest_port=0,
                protocol=Protocol.LOCAL,
                event_type=EventType.PRIV_CHANGE,
                user=d["user"],
                status="SUCCESS",
                details=f"Privilege command executed by {d['user']}: {d['cmd']}",
                raw_line=line,
            )

        # 5. Generic fallback parser: extract IPs and keywords
        ips = IP_RE.findall(line)
        src_ip = ips[0] if ips else "192.168.1.1"
        dst_ip = ips[1] if len(ips) > 1 else "10.0.0.5"

        low = line.lower()
        if "fail" in low or "denied" in low or "unauthorized" in low:
            evt_type = EventType.AUTH_LOGIN
            status = "FAILURE"
        elif "login" in low or "accepted" in low:
            evt_type = EventType.AUTH_LOGIN
            status = "SUCCESS"
        elif "scan" in low or "connect" in low or "port" in low:
            evt_type = EventType.CONNECTION
            status = "ATTEMPT"
        elif "transfer" in low or "exfil" in low or "upload" in low:
            evt_type = EventType.DATA_TRANSFER
            status = "SUCCESS"
        else:
            evt_type = EventType.SYSTEM_EVENT
            status = "INFO"

        return LogEvent(
            timestamp=datetime.utcnow(),
            source_ip=src_ip,
            dest_ip=dst_ip,
            dest_port=80,
            protocol=Protocol.TCP,
            event_type=evt_type,
            user="anonymous",
            status=status,
            bytes_transferred=256,
            details=line[:120],
            raw_line=line,
        )

    @classmethod
    def parse_file(cls, file_path: str | Path) -> list[LogEvent]:
        """Parse an entire file (.log, .txt, .csv, or .jsonl)."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")

        events = []
        suffix = path.suffix.lower()

        if suffix == ".csv":
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    evt = cls._parse_csv_row(row)
                    if evt:
                        events.append(evt)
        else:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    evt = cls.parse_line(line)
                    if evt:
                        events.append(evt)

        return events

    @staticmethod
    def _parse_csv_row(row: dict[str, str]) -> LogEvent | None:
        """Parse standard CSV row or CICIDS-style row."""
        cleaned = {k.strip(): v.strip() for k, v in row.items() if k}

        src_ip = cleaned.get("Source IP") or cleaned.get("source_ip") or "192.168.1.100"
        dst_ip = cleaned.get("Destination IP") or cleaned.get("dest_ip") or "10.0.0.5"
        dst_port_val = cleaned.get("Destination Port") or cleaned.get("dest_port") or "80"
        try:
            dst_port = int(float(dst_port_val))
        except ValueError:
            dst_port = 80

        bytes_val = (
            cleaned.get("Total Length of Fwd Packets")
            or cleaned.get("bytes_transferred")
            or "256"
        )
        try:
            bytes_transferred = int(float(bytes_val))
        except ValueError:
            bytes_transferred = 256

        label = cleaned.get("Label", "BENIGN")

        event_type = EventType.NETWORK_FLOW
        if "PortScan" in label:
            event_type = EventType.CONNECTION
        elif "Patator" in label or "Brute" in label:
            event_type = EventType.AUTH_LOGIN

        return LogEvent(
            timestamp=datetime.utcnow(),
            source_ip=src_ip,
            dest_ip=dst_ip,
            dest_port=dst_port,
            protocol=Protocol.TCP,
            event_type=event_type,
            user=cleaned.get("user", "-"),
            status=cleaned.get("status", "SUCCESS"),
            bytes_transferred=bytes_transferred,
            details=f"Flow to port {dst_port} | Label: {label}",
            label=label,
            raw_line=str(row),
        )


# ══════════════════════════════════════════════════════════════════
# 2. LOG MONITOR (Asynchronous Stream Playback)
# ══════════════════════════════════════════════════════════════════

class LogMonitor:
    """Streams LogEvents sequentially to emulate live network traffic and file ingestion."""

    def __init__(self):
        self.is_running: bool = False
        self.is_paused: bool = False
        self.current_index: int = 0
        self.total_events: int = 0
        self._event_callback: Callable[[LogEvent], Coroutine[Any, Any, None]] | None = None
        self.speed_multiplier: float = 1.0

    def set_callback(self, callback: Callable[[LogEvent], Coroutine[Any, Any, None]]) -> None:
        """Register an async callback invoked for every streamed LogEvent."""
        self._event_callback = callback

    async def start_replay(
        self,
        events: list[LogEvent],
        speed_multiplier: float = 10.0,
        instant: bool = False,
    ) -> None:
        """Start streaming the provided list of events."""
        if self.is_running:
            await self.stop()

        self.is_running = True
        self.is_paused = False
        self.current_index = 0
        self.total_events = len(events)
        self.speed_multiplier = speed_multiplier

        try:
            for idx, event in enumerate(events):
                while self.is_paused and self.is_running:
                    await asyncio.sleep(0.1)

                if not self.is_running:
                    break

                self.current_index = idx + 1

                if self._event_callback:
                    await self._event_callback(event)

                if not instant and speed_multiplier > 0:
                    delay = max(0.01, 0.1 / speed_multiplier)
                    await asyncio.sleep(delay)

        finally:
            self.is_running = False

    async def replay_file(
        self,
        file_path: str | Path,
        speed_multiplier: float = 10.0,
        instant: bool = False,
    ) -> int:
        """Parse a .log, .txt, or .csv file and start replaying it."""
        events = LogParser.parse_file(file_path)
        await self.start_replay(events, speed_multiplier=speed_multiplier, instant=instant)
        return len(events)

    def pause(self) -> None:
        """Pause playback."""
        if self.is_running:
            self.is_paused = True

    def resume(self) -> None:
        """Resume playback."""
        if self.is_running:
            self.is_paused = False

    async def stop(self) -> None:
        """Halt playback."""
        self.is_running = False
        self.is_paused = False

    def get_progress(self) -> dict[str, Any]:
        """Return current playback status."""
        return {
            "is_running": self.is_running,
            "is_paused": self.is_paused,
            "current_index": self.current_index,
            "total_events": self.total_events,
            "percent": round((self.current_index / self.total_events * 100), 1) if self.total_events > 0 else 0.0,
        }


# ══════════════════════════════════════════════════════════════════
# 3. SYNTHETIC LOG GENERATOR (Scenarios & Enterprise False Positives)
# ══════════════════════════════════════════════════════════════════

class SyntheticLogGenerator:
    """Generates synthetic logs and attack scenarios for testing and demonstration."""

    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]
    COMMON_USERS = ["admin", "root", "ubuntu", "operator", "john", "sarah", "guest"]

    def __init__(self, target_ip: str = "10.0.0.5", attacker_ip: str = "192.168.1.105"):
        self.target_ip = target_ip
        self.attacker_ip = attacker_ip

    def generate_port_scan(
        self,
        start_time: datetime,
        attacker_ip: str | None = None,
        ports: list[int] | None = None,
    ) -> list[LogEvent]:
        """Generate port scanning reconnaissance events (MITRE T1046)."""
        attacker = attacker_ip or self.attacker_ip
        target_ports = ports or self.COMMON_PORTS
        events = []
        cur_time = start_time

        for p in target_ports:
            cur_time += timedelta(milliseconds=random.randint(50, 200))
            status = "CLOSED" if p not in (22, 80) else "OPEN"
            evt = LogEvent(
                timestamp=cur_time,
                source_ip=attacker,
                source_port=random.randint(40000, 65000),
                dest_ip=self.target_ip,
                dest_port=p,
                protocol=Protocol.TCP,
                event_type=EventType.CONNECTION,
                user="-",
                status=status,
                bytes_transferred=64,
                details=f"TCP connection probe to port {p} ({status})",
                label="PortScan",
                raw_line=f"{cur_time.isoformat()}Z | CONNECTION | {attacker}:50000 -> {self.target_ip}:{p} | - | {status} | 64 | TCP probe to port {p}",
            )
            events.append(evt)
        return events

    def generate_brute_force(
        self,
        start_time: datetime,
        attacker_ip: str | None = None,
        username: str = "admin",
        failed_attempts: int = 12,
        succeed_at_end: bool = True,
    ) -> list[LogEvent]:
        """Generate targeted SSH brute force attack (MITRE T1110.001)."""
        attacker = attacker_ip or self.attacker_ip
        events = []
        cur_time = start_time

        for i in range(failed_attempts):
            cur_time += timedelta(seconds=random.randint(1, 4))
            evt = LogEvent(
                timestamp=cur_time,
                source_ip=attacker,
                source_port=random.randint(40000, 65000),
                dest_ip=self.target_ip,
                dest_port=22,
                protocol=Protocol.TCP,
                event_type=EventType.AUTH_LOGIN,
                user=username,
                status="FAILURE",
                bytes_transferred=128,
                details=f"SSH authentication failed for user '{username}' (attempt {i+1})",
                label="BruteForce",
                raw_line=f"{cur_time.isoformat()}Z | AUTH_LOGIN | {attacker}:50000 -> {self.target_ip}:22 | {username} | FAILURE | 128 | SSH auth failed attempt {i+1}",
            )
            events.append(evt)

        if succeed_at_end:
            cur_time += timedelta(seconds=2)
            evt = LogEvent(
                timestamp=cur_time,
                source_ip=attacker,
                source_port=random.randint(40000, 65000),
                dest_ip=self.target_ip,
                dest_port=22,
                protocol=Protocol.TCP,
                event_type=EventType.AUTH_LOGIN,
                user=username,
                status="SUCCESS",
                bytes_transferred=512,
                details=f"SSH authentication accepted for user '{username}' - COMPROMISE",
                label="BruteForce_Breach",
                raw_line=f"{cur_time.isoformat()}Z | AUTH_LOGIN | {attacker}:50000 -> {self.target_ip}:22 | {username} | SUCCESS | 512 | SSH auth succeeded after failures",
            )
            events.append(evt)

        return events

    def generate_privilege_escalation(
        self,
        start_time: datetime,
        user: str = "admin",
    ) -> list[LogEvent]:
        """Generate privilege escalation events (MITRE T1068)."""
        events = []
        cur_time = start_time + timedelta(seconds=2)

        evt = LogEvent(
            timestamp=cur_time,
            source_ip="127.0.0.1",
            source_port=0,
            dest_ip=self.target_ip,
            dest_port=0,
            protocol=Protocol.LOCAL,
            event_type=EventType.PRIV_CHANGE,
            user=user,
            status="SUCCESS",
            bytes_transferred=0,
            details=f"User '{user}' executed: sudo -i (spawned root shell via /bin/bash)",
            label="PrivilegeEscalation",
            raw_line=f"{cur_time.isoformat()}Z | PRIV_CHANGE | 127.0.0.1:0 -> {self.target_ip}:0 | {user} | SUCCESS | 0 | sudo -i spawned root shell",
        )
        events.append(evt)
        return events

    def generate_data_exfiltration(
        self,
        start_time: datetime,
        dest_ip: str = "203.0.113.88",
        megabytes: int = 150,
    ) -> list[LogEvent]:
        """Generate mass data exfiltration events (MITRE T1041)."""
        events = []
        cur_time = start_time
        total_bytes = megabytes * 1024 * 1024
        chunk_size = 25 * 1024 * 1024
        chunks = total_bytes // chunk_size

        for i in range(chunks):
            cur_time += timedelta(seconds=random.randint(2, 5))
            evt = LogEvent(
                timestamp=cur_time,
                source_ip=self.target_ip,
                source_port=random.randint(40000, 65000),
                dest_ip=dest_ip,
                dest_port=443,
                protocol=Protocol.TCP,
                event_type=EventType.DATA_TRANSFER,
                user="root",
                status="SUCCESS",
                bytes_transferred=chunk_size,
                details=f"Egress bulk data transfer of {chunk_size // (1024*1024)}MB to external IP {dest_ip}",
                label="DataExfiltration",
                raw_line=f"{cur_time.isoformat()}Z | DATA_TRANSFER | {self.target_ip}:50000 -> {dest_ip}:443 | root | SUCCESS | {chunk_size} | Bulk egress data transfer",
            )
            events.append(evt)
        return events

    def generate_benign_traffic(self, start_time: datetime, count: int = 20) -> list[LogEvent]:
        """Generate normal baseline enterprise background traffic."""
        events = []
        cur_time = start_time
        internal_ips = ["10.0.0.15", "10.0.0.22", "10.0.0.45", "10.0.0.88", "10.0.0.101"]

        for _ in range(count):
            cur_time += timedelta(seconds=random.randint(1, 10))
            src = random.choice(internal_ips)
            port = random.choice([80, 443, 53, 8080])
            evt = LogEvent(
                timestamp=cur_time,
                source_ip=src,
                source_port=random.randint(30000, 60000),
                dest_ip=self.target_ip,
                dest_port=port,
                protocol=Protocol.TCP,
                event_type=EventType.CONNECTION,
                user=random.choice(self.COMMON_USERS),
                status="SUCCESS",
                bytes_transferred=random.randint(256, 4096),
                details=f"Normal internal communication to port {port}",
                label="BENIGN",
                raw_line=f"{cur_time.isoformat()}Z | CONNECTION | {src}:50000 -> {self.target_ip}:{port} | - | SUCCESS | 1024 | Benign internal traffic",
            )
            events.append(evt)
        return events

    def generate_full_attack_chain(self, start_time: datetime | None = None) -> list[LogEvent]:
        """Generate a complete coordinated attack chain across all 4 MITRE phases."""
        start = start_time or datetime.utcnow()
        all_events = []

        all_events.extend(self.generate_benign_traffic(start, count=8))

        t_scan = start + timedelta(seconds=10)
        all_events.extend(self.generate_port_scan(t_scan))

        t_bf = t_scan + timedelta(seconds=20)
        all_events.extend(self.generate_brute_force(t_bf, failed_attempts=10, succeed_at_end=True))

        t_pe = t_bf + timedelta(seconds=15)
        all_events.extend(self.generate_privilege_escalation(t_pe))

        t_ex = t_pe + timedelta(seconds=10)
        all_events.extend(self.generate_data_exfiltration(t_ex))

        all_events.extend(self.generate_benign_traffic(t_ex + timedelta(seconds=10), count=5))
        all_events.sort(key=lambda e: e.timestamp)
        return all_events

    generate_full_scenario = generate_full_attack_chain

    def generate_enterprise_dataset_with_false_positives(self, start_time: datetime | None = None) -> list[LogEvent]:
        """Generate comprehensive 100-event enterprise dataset with realistic false positives and confirmed threats."""
        start = start_time or datetime.utcnow()
        events = []
        cur = start

        # 1. Normal morning traffic baseline
        events.extend(self.generate_benign_traffic(cur, count=15))
        cur += timedelta(seconds=30)

        # 2. FALSE POSITIVE #1: Authorized Vulnerability Scanner (Nessus on 10.0.0.10)
        scanner_ip = "10.0.0.10"
        for p in [21, 22, 25, 80, 110, 139, 443, 445, 1433, 3306, 5432, 8080]:
            cur += timedelta(milliseconds=120)
            events.append(LogEvent(
                timestamp=cur,
                source_ip=scanner_ip,
                source_port=random.randint(40000, 60000),
                dest_ip=self.target_ip,
                dest_port=p,
                protocol=Protocol.TCP,
                event_type=EventType.CONNECTION,
                user="nessus-scanner",
                status="CLOSED" if p not in (22, 80) else "OPEN",
                bytes_transferred=64,
                details=f"Internal vulnerability compliance audit probe to port {p}",
                label="FALSE_POSITIVE_SCAN",
                raw_line=f"{cur.isoformat()}Z | CONNECTION | {scanner_ip}:51200 -> {self.target_ip}:{p} | nessus-scanner | CLOSED | 64 | Internal vuln scan audit probe",
            ))

        cur += timedelta(seconds=20)
        events.extend(self.generate_benign_traffic(cur, count=10))
        cur += timedelta(seconds=20)

        # 3. FALSE POSITIVE #2: Employee Password Typo (Caps Lock)
        employee_ip = "10.0.0.45"
        for i in range(6):
            cur += timedelta(seconds=2)
            events.append(LogEvent(
                timestamp=cur,
                source_ip=employee_ip,
                source_port=52300 + i,
                dest_ip=self.target_ip,
                dest_port=22,
                protocol=Protocol.TCP,
                event_type=EventType.AUTH_LOGIN,
                user="sarah",
                status="FAILURE",
                bytes_transferred=128,
                details=f"SSH auth failure for employee 'sarah' from internal workstation (caps-lock typo {i+1})",
                label="FALSE_POSITIVE_TYPO",
                raw_line=f"{cur.isoformat()}Z | AUTH_LOGIN | {employee_ip}:52300 -> {self.target_ip}:22 | sarah | FAILURE | 128 | Employee workstation typo attempt {i+1}",
            ))

        # Immediate success
        cur += timedelta(seconds=3)
        events.append(LogEvent(
            timestamp=cur,
            source_ip=employee_ip,
            source_port=52310,
            dest_ip=self.target_ip,
            dest_port=22,
            protocol=Protocol.TCP,
            event_type=EventType.AUTH_LOGIN,
            user="sarah",
            status="SUCCESS",
            bytes_transferred=512,
            details="SSH authentication accepted for employee 'sarah' from assigned corporate workstation",
            label="BENIGN",
            raw_line=f"{cur.isoformat()}Z | AUTH_LOGIN | {employee_ip}:52310 -> {self.target_ip}:22 | sarah | SUCCESS | 512 | SSH accepted for sarah",
        ))

        cur += timedelta(seconds=30)
        events.extend(self.generate_benign_traffic(cur, count=10))
        cur += timedelta(seconds=20)

        # 4. TRUE ATTACK #1: External Reconnaissance Port Scan
        attacker_recon = "198.51.100.42"
        for p in [21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080, 8443]:
            cur += timedelta(milliseconds=80)
            events.append(LogEvent(
                timestamp=cur,
                source_ip=attacker_recon,
                source_port=random.randint(45000, 65000),
                dest_ip=self.target_ip,
                dest_port=p,
                protocol=Protocol.TCP,
                event_type=EventType.CONNECTION,
                user="-",
                status="CLOSED" if p not in (22, 80) else "OPEN",
                bytes_transferred=64,
                details=f"Malicious external TCP SYN probe to port {p}",
                label="PortScan",
                raw_line=f"{cur.isoformat()}Z | CONNECTION | {attacker_recon}:49100 -> {self.target_ip}:{p} | - | CLOSED | 64 | External reconnaissance probe",
            ))

        cur += timedelta(seconds=25)

        # 5. TRUE ATTACK #2: External SSH Brute Force & Breach
        events.extend(self.generate_brute_force(cur, attacker_ip=self.attacker_ip, username="admin", failed_attempts=12, succeed_at_end=True))
        cur += timedelta(seconds=40)

        # 6. FALSE POSITIVE #3: Scheduled Nightly Database Backup (Internal NAS)
        backup_ip = "10.0.0.200"
        events.append(LogEvent(
            timestamp=cur,
            source_ip="10.0.0.5",
            source_port=44500,
            dest_ip=backup_ip,
            dest_port=445,
            protocol=Protocol.TCP,
            event_type=EventType.DATA_TRANSFER,
            user="backup-svc",
            status="SUCCESS",
            bytes_transferred=125 * 1024 * 1024,
            details="Scheduled database backup synchronization to internal storage NAS (10.0.0.200)",
            label="FALSE_POSITIVE_BACKUP",
            raw_line=f"{cur.isoformat()}Z | DATA_TRANSFER | 10.0.0.5:44500 -> {backup_ip}:445 | backup-svc | SUCCESS | 131072000 | Routine NAS backup sync",
        ))

        cur += timedelta(seconds=30)

        # 7. FALSE POSITIVE #4: Sysadmin Routine Maintenance (apt update)
        sysadmin_ip = "10.0.0.50"
        events.append(LogEvent(
            timestamp=cur,
            source_ip=sysadmin_ip,
            source_port=51100,
            dest_ip="10.0.0.5",
            dest_port=0,
            protocol=Protocol.LOCAL,
            event_type=EventType.PRIV_CHANGE,
            user="john",
            status="SUCCESS",
            bytes_transferred=0,
            details="Privileged command executed: sudo apt-get update && sudo apt-get -y upgrade",
            label="FALSE_POSITIVE_SYSADMIN",
            raw_line=f"{cur.isoformat()}Z | PRIV_CHANGE | {sysadmin_ip}:51100 -> 10.0.0.5:0 | john | SUCCESS | 0 | sudo apt-get update package maintenance",
        ))

        cur += timedelta(seconds=20)

        # 8. TRUE ATTACK #3: Privilege Escalation to Root
        events.extend(self.generate_privilege_escalation(cur, user="admin"))
        cur += timedelta(seconds=20)

        # 9. TRUE ATTACK #4: Mass Data Exfiltration to External C2
        events.extend(self.generate_data_exfiltration(cur, dest_ip="203.0.113.88", megabytes=150))
        cur += timedelta(seconds=20)

        # 10. Trailing normal traffic
        events.extend(self.generate_benign_traffic(cur, count=10))

        events.sort(key=lambda e: e.timestamp)
        return events

    def export_scenario_to_file(self, events: list[LogEvent], output_path: str | Path) -> Path:
        """Export a list of LogEvents to a file in structured text format."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            for evt in events:
                f.write(evt.raw_line + "\n")
        return path
