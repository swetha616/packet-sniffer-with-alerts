#!/usr/bin/env python3
"""
Packet sniffer + SQLite logging + anomaly detection + alerts + optional GUI

Features:
 - Capture packets with scapy
 - Buffered batch writes to SQLite (to avoid per-packet disk overhead)
 - Anomaly detection: port-scan, flooding, SYN pattern
 - Alerts persisted to DB and printed to console; optional SMTP email
 - CLI summary mode (--summary)
 - Optional matplotlib GUI (--gui) showing:
     * Live packets-per-second (PPS) line
     * Protocol usage pie chart (TCP / UDP / OTHER)
 - Verbose printing (--verbose), demo count (--count), and helpful CLI flags

Run (Linux/macOS): sudo python sniffer.py --filter "ip" --gui
Run (Windows PowerShell as Admin): python sniffer.py --filter "ip" --gui
"""

from __future__ import annotations

import argparse
import os
import queue
import signal
import sqlite3
import smtplib
import sys
import threading
import time
from collections import defaultdict, deque
from contextlib import closing
from dataclasses import dataclass
from email.mime.text import MIMEText
from typing import Optional, Tuple, List, Dict

# scapy
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP  # type: ignore
except Exception:
    print("[!] scapy not installed. Install with: pip install scapy")
    raise

# matplotlib (optional)
try:
    import matplotlib.pyplot as plt  # type: ignore
    import matplotlib.animation as animation  # type: ignore
    HAS_MATPLOTLIB = True
except Exception:
    HAS_MATPLOTLIB = False

# -------------------------- Database Schema & Layer ------------------------ #
SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    src TEXT,
    dst TEXT,
    proto TEXT,
    sport INTEGER,
    dport INTEGER,
    length INTEGER,
    flags TEXT
);
CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts);
CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src);
CREATE INDEX IF NOT EXISTS idx_packets_dst ON packets(dst);
CREATE INDEX IF NOT EXISTS idx_packets_proto ON packets(proto);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    src TEXT,
    dst TEXT,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
"""

class DB:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        with closing(self.conn.cursor()) as cur:
            cur.executescript(SCHEMA_SQL)
        self.lock = threading.Lock()

    def insert_packets_batch(self, rows: List[Tuple[float, Optional[str], Optional[str], str, Optional[int], Optional[int], Optional[int], Optional[str]]]):
        if not rows:
            return
        with self.lock:
            self.conn.executemany(
                "INSERT INTO packets(ts,src,dst,proto,sport,dport,length,flags) VALUES (?,?,?,?,?,?,?,?)",
                rows
            )
            self.conn.commit()

    def insert_alert(self, ts: float, type_: str, severity: str, src: Optional[str], dst: Optional[str], detail: str):
        with self.lock:
            self.conn.execute(
                "INSERT INTO alerts(ts,type,severity,src,dst,detail) VALUES (?,?,?,?,?,?)",
                (ts, type_, severity, src, dst, detail)
            )
            self.conn.commit()

    def query(self, sql: str, params: tuple = ()):
        with self.lock:
            cur = self.conn.execute(sql, params)
            rows = cur.fetchall()
        return rows

    def close(self):
        with self.lock:
            self.conn.close()

# ------------------------------- Thresholds -------------------------------- #
@dataclass
class Thresholds:
    portscan_unique_ports: int = 20
    portscan_window_sec: float = 5.0
    flood_pps: int = 200
    flood_window_sec: float = 1.0
    syn_ratio_threshold: float = 0.9
    syn_window_sec: float = 5.0

# ---------------------------- Anomaly Detector ------------------------------ #
class AnomalyDetector:
    def __init__(self, db: DB, th: Thresholds, email_conf: Optional[Dict] = None, cooldown_sec: int = 30):
        self.db = db
        self.th = th
        self.email_conf = email_conf or {}
        # windows and state
        self.scan_window: Dict[Tuple[str, str], deque] = defaultdict(deque)
        self.flood_window: Dict[str, deque] = defaultdict(deque)
        self.syn_window: Dict[str, deque] = defaultdict(deque)
        self.alert_cooldown: Dict[Tuple[str, str], float] = {}
        self.cooldown_sec = cooldown_sec

    def _maybe_alert(self, type_: str, severity: str, src: Optional[str], dst: Optional[str], detail: str):
        key = (type_, f"{src}->{dst}")
        now = time.time()
        last = self.alert_cooldown.get(key, 0.0)
        if now - last < self.cooldown_sec:
            return
        self.alert_cooldown[key] = now
        # persist + print
        self.db.insert_alert(now, type_, severity, src, dst, detail)
        print(f"\n[ALERT] {type_} ({severity}) src={src} dst={dst} :: {detail}\n")
        # optional email
        try:
            self._send_email(type_, severity, src, dst, detail)
        except Exception as e:
            print(f"[!] Email send failed: {e}")

    def _send_email(self, type_, severity, src, dst, detail):
        if not self.email_conf.get("to"):
            return
        body = f"Type: {type_}\nSeverity: {severity}\nSource: {src}\nDestination: {dst}\nDetail: {detail}\nTime: {time.ctime()}"
        msg = MIMEText(body)
        msg["Subject"] = f"[Sniffer Alert] {type_} — {severity}"
        msg["From"] = self.email_conf.get("user", "sniffer@localhost")
        msg["To"] = self.email_conf["to"]
        server = self.email_conf.get("server", "localhost")
        port = int(self.email_conf.get("port", 25))
        user = self.email_conf.get("user")
        password = self.email_conf.get("password")
        use_tls = bool(self.email_conf.get("tls", True))
        with smtplib.SMTP(server, port, timeout=10) as s:
            if use_tls:
                s.starttls()
            if user and password:
                s.login(user, password)
            s.send_message(msg)

    def observe(self, ts: float, src: Optional[str], dst: Optional[str], proto: str,
                sport: Optional[int], dport: Optional[int], flags: Optional[str]) -> None:
        # Port-scan detection (src->dst many distinct dports)
        if dport is not None and src and dst:
            key = (src, dst)
            dq = self.scan_window[key]
            dq.append((ts, dport))
            while dq and ts - dq[0][0] > self.th.portscan_window_sec:
                dq.popleft()
            distinct = len({p for _, p in dq})
            if distinct >= self.th.portscan_unique_ports:
                self._maybe_alert("PortScan", "high", src, dst,
                                  f"{distinct} distinct destination ports within {self.th.portscan_window_sec}s")
        # Flood detection (packets per second from src)
        if src:
            dqf = self.flood_window[src]
            dqf.append(ts)
            while dqf and ts - dqf[0] > self.th.flood_window_sec:
                dqf.popleft()
            rate = len(dqf) / max(self.th.flood_window_sec, 1e-6)
            if rate >= self.th.flood_pps:
                sev = "critical" if rate > self.th.flood_pps * 2 else "high"
                self._maybe_alert("Flood", sev, src, None, f"~{rate:.0f} pps over last {self.th.flood_window_sec}s")
        # SYN pattern detection
        if proto == "TCP" and src:
            is_syn = flags is not None and "S" in flags
            is_ack = flags is not None and "A" in flags
            dqs = self.syn_window[src]
            dqs.append((ts, is_syn, is_ack))
            while dqs and ts - dqs[0][0] > self.th.syn_window_sec:
                dqs.popleft()
            syns = sum(1 for _, s, _ in dqs if s)
            acks = sum(1 for _, _, a in dqs if a)
            total = max(1, syns + acks)
            ratio = syns / total
            if syns >= 30 and ratio >= self.th.syn_ratio_threshold:
                self._maybe_alert("SYN-Flood-Pattern", "medium", src, None,
                                  f"SYN/ACK ratio {ratio:.2f} over {self.th.syn_window_sec}s (syns={syns}, acks={acks})")

# --------------------------- Buffered DB Writer ------------------------------ #
class DBWriter(threading.Thread):
    def __init__(self, db: DB, q: queue.Queue, batch_size: int = 200, flush_interval: float = 1.0):
        super().__init__(daemon=True)
        self.db = db
        self.q = q
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._stop = threading.Event()

    def run(self):
        buffer: List[Tuple[float, Optional[str], Optional[str], str, Optional[int], Optional[int], Optional[int], Optional[str]]] = []
        last_flush = time.time()
        while not self._stop.is_set():
            try:
                item = self.q.get(timeout=0.25)
                if item is None:
                    break  # sentinel
                buffer.append(item)
                if len(buffer) >= self.batch_size:
                    self._flush(buffer)
                    buffer = []
                    last_flush = time.time()
            except queue.Empty:
                if buffer and (time.time() - last_flush) >= self.flush_interval:
                    self._flush(buffer)
                    buffer = []
                    last_flush = time.time()
        if buffer:
            self._flush(buffer)

    def _flush(self, buffer: List):
        try:
            self.db.insert_packets_batch(buffer)
        except Exception as e:
            print(f"[!] DBWriter flush error: {e}")

    def stop(self):
        self._stop.set()
        try:
            self.q.put_nowait(None)
        except Exception:
            pass

# -------------------------------- Sniffer ----------------------------------- #
class Sniffer:
    def __init__(self, iface: Optional[str], bpf_filter: Optional[str], dbq: queue.Queue,
                 detector: Optional[AnomalyDetector], enable_detection: bool = True,
                 verbose: bool = False, limit_rate: float = 0.0, count_limit: Optional[int] = None,
                 metrics: Optional[dict] = None):
        self.iface = iface
        self.filter = bpf_filter
        self.dbq = dbq
        self.detector = detector
        self.enable_detection = enable_detection and (detector is not None)
        self.verbose = verbose
        self.limit_rate = limit_rate
        self._stop = threading.Event()
        self.count = 0
        self.count_limit = count_limit
        self.metrics = metrics if metrics is not None else {'pkt_count': 0, 'prev_pkt_count': 0, 'last_ts': 0, 'proto_counts': defaultdict(int)}
        self._last_verbose = 0.0

    def _format_packet(self, ts, src, dst, proto, sport, dport, length, flags):
        t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        return f"{t} | {proto:5} | {src or '-':21} -> {dst or '-':21} | sport={sport or '-'} dport={dport or '-'} len={length or '-'} flags={flags or '-'}"

    def _packet_handler(self, pkt):
        try:
            ts = time.time()
            src = dst = None
            proto = "OTHER"
            sport = dport = None
            length = int(len(pkt)) if pkt is not None else None
            flags_str = None

            if IP in pkt:
                ip = pkt[IP]
                src = ip.src
                dst = ip.dst
                if TCP in pkt:
                    tcp = pkt[TCP]
                    proto = "TCP"
                    try:
                        sport = int(tcp.sport)
                        dport = int(tcp.dport)
                    except Exception:
                        sport = None; dport = None
                    flags_str = str(tcp.flags) if hasattr(tcp, 'flags') else None
                elif UDP in pkt:
                    udp = pkt[UDP]
                    proto = "UDP"
                    try:
                        sport = int(udp.sport)
                        dport = int(udp.dport)
                    except Exception:
                        sport = None; dport = None
                elif ICMP in pkt:
                    proto = "ICMP"
                else:
                    proto = "IP"
            else:
                proto = "OTHER"

            # queue for DB writer
            row = (ts, src, dst, proto, sport, dport, length, flags_str)
            try:
                self.dbq.put_nowait(row)
            except queue.Full:
                # drop silently to preserve capture
                pass

            # metrics for GUI/live
            self.metrics['last_ts'] = ts
            self.metrics['pkt_count'] = self.metrics.get('pkt_count', 0) + 1
            proto_counts = self.metrics.get('proto_counts')
            if proto_counts is None:
                proto_counts = defaultdict(int)
                self.metrics['proto_counts'] = proto_counts
            proto_counts[proto] = proto_counts.get(proto, 0) + 1

            # detection
            if self.enable_detection and self.detector:
                self.detector.observe(ts, src, dst, proto, sport, dport, flags_str)

            # verbose printing (respect limit_rate prints/sec)
            now = time.time()
            if self.verbose:
                if self.limit_rate <= 0.0 or (now - self._last_verbose) >= (1.0 / max(self.limit_rate, 1e-6)):
                    print(self._format_packet(ts, src, dst, proto, sport, dport, length, flags_str))
                    self._last_verbose = now

            # demo count limit
            self.count += 1
            if self.count_limit and self.count >= self.count_limit:
                self.stop()

        except Exception as e:
            print(f"[!] Handler error: {e}")

    def start(self):
        print("[*] Starting capture... Press Ctrl+C to stop.")
        try:
            sniff(
                iface=self.iface,
                filter=self.filter,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda x: self._stop.is_set()
            )
        except Exception as e:
            print(f"[!] sniff error: {e}")
        finally:
            print("[*] Capture stopped.")

    def stop(self):
        self._stop.set()

# ------------------------- Traffic Summary Utils ---------------------------- #
def traffic_summary(db: DB, top_n: int = 10):
    print("\n=== Traffic Summary ===")
    rows = db.query("SELECT COUNT(*) FROM packets")
    total = rows[0][0] if rows else 0
    print(f"Total packets stored: {total}")
    rows = db.query("SELECT src, COUNT(*) as cnt FROM packets GROUP BY src ORDER BY cnt DESC LIMIT ?", (top_n,))
    print("Top sources:")
    for r in rows:
        print(f"  {r[0]} — {r[1]} packets")
    rows = db.query("SELECT dst, COUNT(*) as cnt FROM packets GROUP BY dst ORDER BY cnt DESC LIMIT ?", (top_n,))
    print("Top destinations:")
    for r in rows:
        print(f"  {r[0]} — {r[1]} packets")
    rows = db.query("SELECT proto, COUNT(*) FROM packets GROUP BY proto ORDER BY COUNT(*) DESC")
    print("Protocols:")
    for r in rows:
        print(f"  {r[0]} — {r[1]}")
    rows = db.query("SELECT ts,type,severity,src,dst,detail FROM alerts ORDER BY ts DESC LIMIT 10")
    if rows:
        print("Recent alerts:")
        for r in rows:
            print(f"  {time.ctime(r[0])}: {r[1]} ({r[2]}) src={r[3]} dst={r[4]} -> {r[5]}")
    else:
        print("No alerts recorded.")
    print("=== End Summary ===\n")

# ----------------------------- Live Dashboard ------------------------------- #
class LiveDashboard:
    def __init__(self, metrics: dict, pps_window: int = 30, pie_update_interval: int = 3):
        if not HAS_MATPLOTLIB:
            raise RuntimeError("matplotlib not installed; install with: pip install matplotlib")
        self.metrics = metrics
        self.pps_window = pps_window
        self.pie_update_interval = pie_update_interval
        self.history = deque()  # list of (timestamp, pps)
        self.last_pie_update = 0.0

        self.fig, (self.ax_line, self.ax_pie) = plt.subplots(ncols=2, figsize=(10,4))
        self.line_plot, = self.ax_line.plot([], [], lw=2)
        self.ax_line.set_title("Packets per second (last {}s)".format(self.pps_window))
        self.ax_line.set_xlim(-self.pps_window, 0)
        self.ax_line.set_ylim(0, 10)  # will autoscale later

        self.pie_wedges = None
        self.pie_texts = None
        self.ax_pie.set_title("Protocol usage (live)")

    def _update_history(self):
        now = time.time()
        curr = self.metrics.get('pkt_count', 0)
        prev = self.metrics.get('prev_pkt_count', 0)
        pps = curr - prev
        if pps < 0:
            pps = 0
        self.metrics['prev_pkt_count'] = curr
        self.history.append((now, pps))
        # trim
        while self.history and now - self.history[0][0] > self.pps_window:
            self.history.popleft()

    def _get_line_data(self):
        now = time.time()
        xs = [t - now for t, _ in self.history]
        ys = [v for _, v in self.history]
        return xs, ys

    def _get_proto_snapshot(self):
        proto_counts = self.metrics.get('proto_counts', {})
        # normalize keys to TCP/UDP/OTHER
        tcp = proto_counts.get('TCP', 0)
        udp = proto_counts.get('UDP', 0)
        other = sum(v for k, v in proto_counts.items() if k not in ('TCP', 'UDP'))
        return {'TCP': tcp, 'UDP': udp, 'OTHER': other}

    def animate(self, frame):
        try:
            self._update_history()
            xs, ys = self._get_line_data()
            if ys:
                ymax = max(10, max(ys) * 1.3)
                self.ax_line.set_ylim(0, ymax)
            self.line_plot.set_data(xs, ys)
            # pie chart periodically (every pie_update_interval seconds)
            now = time.time()
            if now - self.last_pie_update >= self.pie_update_interval:
                snapshot = self._get_proto_snapshot()
                labels = []
                sizes = []
                for k in ('TCP', 'UDP', 'OTHER'):
                    labels.append(k)
                    sizes.append(snapshot.get(k, 0))
                total = sum(sizes)
                # avoid empty pie
                if total == 0:
                    sizes = [1, 1, 1]
                    labels = ['TCP', 'UDP', 'OTHER']
                self.ax_pie.clear()
                self.ax_pie.set_title("Protocol usage (live)")
                self.ax_pie.pie(sizes, labels=labels, autopct=lambda pct: ("{:.0f}").format(pct*total/100) if total>0 else "", startangle=90)
                self.last_pie_update = now
            # layout adjustments
            self.ax_line.relim()
            self.ax_line.autoscale_view()
            return self.line_plot,
        except Exception as e:
            # don't crash animation loop
            print(f"[!] Dashboard animate error: {e}")
            return self.line_plot,

    def start(self):
        ani = animation.FuncAnimation(self.fig, self.animate, interval=1000, blit=False)
        plt.tight_layout()
        plt.show()

# -------------------------------- CLI / Main -------------------------------- #
def parse_args():
    p = argparse.ArgumentParser(description="Network Packet Sniffer with Alert System (Complete)")
    p.add_argument('--iface', help='Network interface (e.g., eth0, Wi-Fi)', default=None)
    p.add_argument('--filter', help='BPF filter (e.g., \"tcp or udp\" or \"ip\")', default=None)
    p.add_argument('--db', help='SQLite DB path', default='traffic.db')
    p.add_argument('--no-detect', help='Disable anomaly detection', action='store_true')
    p.add_argument('--summary', help='Show traffic summary from DB and exit', action='store_true')
    p.add_argument('--gui', help='Show live graph (matplotlib) while capturing', action='store_true')
    p.add_argument('--verbose', help='Print every packet header to console', action='store_true')
    p.add_argument('--limit-rate', type=float, default=0.0, help='Max prints/sec when verbose (0 = no limit)')
    p.add_argument('--count', type=int, default=0, help='Stop after N packets (useful for demos). 0 = unlimited')

    # thresholds
    p.add_argument('--portscan-ports', type=int, default=20)
    p.add_argument('--portscan-window', type=float, default=5.0)
    p.add_argument('--flood-pps', type=int, default=200)
    p.add_argument('--flood-window', type=float, default=1.0)
    p.add_argument('--syn-ratio', type=float, default=0.9)
    p.add_argument('--syn-window', type=float, default=5.0)

    # email
    p.add_argument('--email-to', default=os.getenv('ALERT_TO'))
    p.add_argument('--smtp-server', default=os.getenv('SMTP_SERVER'))
    p.add_argument('--smtp-port', type=int, default=int(os.getenv('SMTP_PORT', '587')))
    p.add_argument('--smtp-user', default=os.getenv('SMTP_USER'))
    p.add_argument('--smtp-pass', default=os.getenv('SMTP_PASS'))
    p.add_argument('--smtp-no-tls', action='store_true')

    return p.parse_args()

def main():
    args = parse_args()
    db = DB(args.db)

    if args.summary:
        traffic_summary(db)
        db.close()
        return

    th = Thresholds(
        portscan_unique_ports=args.portscan_ports,
        portscan_window_sec=args.portscan_window,
        flood_pps=args.flood_pps,
        flood_window_sec=args.flood_window,
        syn_ratio_threshold=args.syn_ratio,
        syn_window_sec=args.syn_window
    )

    email_conf = {
        "to": args.email_to,
        "server": args.smtp_server,
        "port": args.smtp_port,
        "user": args.smtp_user,
        "password": args.smtp_pass,
        "tls": not args.smtp_no_tls
    }

    detector = AnomalyDetector(db, th, email_conf)

    # DB queue & writer
    db_queue: queue.Queue = queue.Queue(maxsize=20000)
    db_writer = DBWriter(db, db_queue, batch_size=200, flush_interval=1.0)
    db_writer.start()

    metrics = {'pkt_count': 0, 'prev_pkt_count': 0, 'last_ts': 0, 'proto_counts': defaultdict(int)}

    sniffer = Sniffer(
        iface=args.iface,
        bpf_filter=args.filter,
        dbq=db_queue,
        detector=detector,
        enable_detection=not args.no_detect,
        verbose=args.verbose,
        limit_rate=args.limit_rate,
        count_limit=(args.count if args.count > 0 else None),
        metrics=metrics
    )

    def handle_sig(sig, frame):
        print("\n[*] Signal received, stopping...")
        sniffer.stop()

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    capture_thread = threading.Thread(target=sniffer.start, daemon=True)
    capture_thread.start()

    try:
        if args.gui:
            if not HAS_MATPLOTLIB:
                print("[!] matplotlib not available. Install with: pip install matplotlib")
            else:
                dashboard = LiveDashboard(metrics)
                dashboard.start()
        else:
            while capture_thread.is_alive():
                capture_thread.join(timeout=1)
    except KeyboardInterrupt:
        sniffer.stop()
    finally:
        print("[*] Shutting down...")
    
        sniffer.stop()
        sniffer.join(timeout=3)

        db_writer.stop()
        db_writer.join(timeout=3)
        db.close()
        print("[*] Done.")


if __name__ == '__main__':
    main()

