# windows_python_ids_with_webhook.py
import time
from scapy.all import sniff, TCP, IP, Raw, get_if_list
from collections import defaultdict, deque
import re
import threading
from colorama import Fore, Style, init
import logging
import requests
from queue import Queue, Empty
import json

init(autoreset=True)

# ------------- Configuration -------------
INTERFACE = None   # None -> scapy chooses default. Set to interface index number (shown below) or name
ALERT_LOGFILE = "ids_alerts.log"
WEBHOOK_URL = "http://localhost:5678/webhook-test/snort-alert"  # <--- your webhook

# Simple blacklists and signatures (edit as needed)
BLACKLISTED_IPS = {
    "203.0.113.10",  # example bad IPs (replace with real ones)
}

SUSPICIOUS_PATTERNS = [
    re.compile(rb"(?i)password"),
    re.compile(rb"(?i)cmd\.exe"),
    re.compile(rb"(?i)powershell"),
    re.compile(rb"(?i)wget "),
    re.compile(rb"(?i)curl "),
    re.compile(rb"(?i)nc -l"),
    # Add more binary/text patterns as needed
]

# Detection thresholds (tune to your network)
PORT_SCAN_PORTS_THRESHOLD = 20      # distinct dest ports within WINDOW -> port-scan
PORT_SCAN_WINDOW = 10.0             # seconds
SYN_FLOOD_THRESHOLD = 200          # SYN packets to same dst within WINDOW -> syn-flood
SYN_FLOOD_WINDOW = 5.0
BRUTE_FORCE_ATTEMPTS = 50          # connection attempts to same dst:port within WINDOW
BRUTE_FORCE_WINDOW = 300.0

# ------------- Internal state -------------
src_to_dstports = defaultdict(lambda: deque())     # src -> deque of (timestamp, dstport)
dst_syn_counters = defaultdict(lambda: deque())    # (dstip,dstport) -> deque timestamps
dst_conn_attempts = defaultdict(lambda: deque())   # (dstip,dstport) -> deque timestamps

# Setup logging
logging.basicConfig(
    filename=ALERT_LOGFILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# Webhook queue and worker
webhook_q = Queue()
WEBHOOK_TIMEOUT = 5
WEBHOOK_RETRIES = 2
WEBHOOK_BACKOFF = 1.0

def webhook_worker():
    while True:
        try:
            alert = webhook_q.get()
            if alert is None:
                break
            for attempt in range(1, WEBHOOK_RETRIES + 2):
                try:
                    resp = requests.post(WEBHOOK_URL, json=alert, timeout=WEBHOOK_TIMEOUT)
                    if 200 <= resp.status_code < 300:
                        logging.info(f"Webhook posted successfully: {alert.get('alert_type')} -> {resp.status_code}")
                        break
                    else:
                        logging.warning(f"Webhook returned status {resp.status_code}: {resp.text}")
                except Exception as e:
                    logging.warning(f"Webhook post attempt {attempt} failed: {e}")
                time.sleep(WEBHOOK_BACKOFF * attempt)
            webhook_q.task_done()
        except Exception as ex:
            logging.exception(f"Exception in webhook worker: {ex}")

# Start worker thread (daemon so it won't block exit)
t = threading.Thread(target=webhook_worker, daemon=True)
t.start()

# ------------- Helper functions -------------
def enqueue_webhook(alert_dict):
    try:
        webhook_q.put_nowait(alert_dict)
    except Exception as e:
        logging.warning(f"Failed to enqueue webhook alert: {e}")

def log_alert(msg, alert_dict=None):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    console = f"{Fore.RED}{ts} ALERT: {msg}{Style.RESET_ALL}"
    print(console)
    logging.info(msg)
    if alert_dict is not None:
        enqueue_webhook(alert_dict)

def clean_old_entries(deq, window):
    now = time.time()
    while deq and (now - deq[0]) > window:
        deq.popleft()

def check_port_scan(src_ip, dst_port):
    dq = src_to_dstports[src_ip]
    now = time.time()
    dq.append((now, dst_port))
    while dq and (now - dq[0][0]) > PORT_SCAN_WINDOW:
        dq.popleft()
    distinct_ports = {p for _, p in dq}
    if len(distinct_ports) >= PORT_SCAN_PORTS_THRESHOLD:
        return True, len(distinct_ports)
    return False, len(distinct_ports)

def check_syn_flood(dst_ip, dst_port):
    key = (dst_ip, dst_port)
    dq = dst_syn_counters[key]
    now = time.time()
    dq.append(now)
    clean_old_entries(dq, SYN_FLOOD_WINDOW)
    if len(dq) >= SYN_FLOOD_THRESHOLD:
        return True, len(dq)
    return False, len(dq)

def check_bruteforce(dst_ip, dst_port):
    key = (dst_ip, dst_port)
    dq = dst_conn_attempts[key]
    now = time.time()
    dq.append(now)
    clean_old_entries(dq, BRUTE_FORCE_WINDOW)
    if len(dq) >= BRUTE_FORCE_ATTEMPTS:
        return True, len(dq)
    return False, len(dq)

def payload_matches(raw_bytes):
    if not raw_bytes:
        return None
    for patt in SUSPICIOUS_PATTERNS:
        if patt.search(raw_bytes):
            # return readable representation of pattern
            try:
                return patt.pattern.decode('latin1', errors='ignore')
            except Exception:
                return str(patt.pattern)
    return None

# ------------- Packet processing -------------
def make_alert_dict(alert_type, msg, pkt=None, extra=None):
    alert = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "alert_type": alert_type,
        "message": msg
    }
    if pkt is not None:
        try:
            alert["pkt_summary"] = pkt.summary()
        except Exception:
            alert["pkt_summary"] = str(pkt)
        try:
            if IP in pkt:
                alert["src_ip"] = pkt[IP].src
                alert["dst_ip"] = pkt[IP].dst
            if TCP in pkt:
                alert["src_port"] = int(pkt[TCP].sport)
                alert["dst_port"] = int(pkt[TCP].dport)
        except Exception:
            pass
    if extra:
        alert.update(extra)
    return alert

def process_packet(pkt):
    try:
        if IP in pkt:
            ip_layer = pkt[IP]
            src = ip_layer.src
            dst = ip_layer.dst

            # Blacklisted IP
            if src in BLACKLISTED_IPS or dst in BLACKLISTED_IPS:
                msg = f"BLACKLISTED IP seen: src={src} dst={dst} pkt_summary={pkt.summary()}"
                alert = make_alert_dict("blacklist", msg, pkt)
                log_alert(msg, alert)

            # TCP checks
            if TCP in pkt:
                tcp = pkt[TCP]
                flags = tcp.flags

                # SYN packet (possible scan / syn-flood)
                if flags & 0x02:  # SYN set
                    # Port-scan heuristic
                    spotted_scan, count_ports = check_port_scan(src, tcp.dport)
                    if spotted_scan:
                        msg = f"PORT-SCAN detected from {src} -> {dst}:{tcp.dport} (distinct ports in {PORT_SCAN_WINDOW}s: {count_ports})"
                        alert = make_alert_dict("port-scan", msg, pkt, {"distinct_ports": count_ports})
                        log_alert(msg, alert)
                        src_to_dstports[src].clear()

                    # SYN-FLOOD heuristic
                    spotted_synf, syn_count = check_syn_flood(dst, tcp.dport)
                    if spotted_synf:
                        msg = f"SYN-FLOOD suspected at {dst}:{tcp.dport} (SYNs in {SYN_FLOOD_WINDOW}s: {syn_count})"
                        alert = make_alert_dict("syn-flood", msg, pkt, {"syn_count": syn_count})
                        log_alert(msg, alert)
                        dst_syn_counters[(dst, tcp.dport)].clear()

                    # Brute-force heuristic
                    spotted_brute, attempts = check_bruteforce(dst, tcp.dport)
                    if spotted_brute:
                        msg = f"POTENTIAL BRUTE-FORCE at {dst}:{tcp.dport} (attempts in {BRUTE_FORCE_WINDOW}s: {attempts})"
                        alert = make_alert_dict("brute-force", msg, pkt, {"attempts": attempts})
                        log_alert(msg, alert)
                        dst_conn_attempts[(dst, tcp.dport)].clear()

                # Application/Raw payload inspection (if present)
                raw_bytes = None
                if Raw in pkt:
                    raw_bytes = bytes(pkt[Raw].load)
                    patt = payload_matches(raw_bytes)
                    if patt:
                        msg = f"Suspicious payload pattern '{patt}' detected in packet {src} -> {dst}:{tcp.dport} summary={pkt.summary()}"
                        alert = make_alert_dict("suspicious-payload", msg, pkt, {"pattern": patt})
                        log_alert(msg, alert)

            # UDP or other protocols: simple payload inspection
            else:
                if Raw in pkt:
                    raw_bytes = bytes(pkt[Raw].load)
                    patt = payload_matches(raw_bytes)
                    if patt:
                        msg = f"Suspicious payload pattern '{patt}' in non-TCP packet {src}->{dst} summary={pkt.summary()}"
                        alert = make_alert_dict("suspicious-payload", msg, pkt, {"pattern": patt})
                        log_alert(msg, alert)

    except Exception as e:
        # keep sniffer running even if one packet handling fails
        logging.exception(f"Exception processing packet: {e}")

# ------------- Runner / interface selection -------------
def list_ifaces():
    print("Available interfaces:")
    for i, iface in enumerate(get_if_list()):
        print(f"  [{i}] {iface}")

def run_sniffer():
    print("Starting IDS sniffer. Press Ctrl+C to stop.")
    sniff(prn=process_packet, store=False, iface=INTERFACE)

if __name__ == "__main__":
    print("Simple Python IDS (Windows) — with webhook forwarding")
    list_ifaces()
    if INTERFACE:
        print(f"Using configured interface: {INTERFACE}")
    else:
        print("No INTERFACE set; scapy will use default. If you want a specific one, edit INTERFACE variable in the script.")
    try:
        run_sniffer()
    except KeyboardInterrupt:
        print("\nStopping sniffer.")
    except PermissionError:
        print("Permission error: you must run this script as Administrator and have Npcap installed.")
    finally:
        # Clean shutdown: signal worker to exit
        try:
            webhook_q.put(None)
            t.join(timeout=2)
        except Exception:
            pass
