from flask import Flask, jsonify, render_template
import threading, datetime, socket

try:
    import scapy.all as scapy
    sniff = scapy.sniff
    SCAPY = scapy
except Exception:
    scapy = None
    sniff = None
    SCAPY = None

app = Flask(__name__)

monitoring = False
packets = []
logs = []
lock = threading.Lock()
sniff_thread = None

PORT_SERVICES = {80: "HTTP", 53: "DNS", 22: "SSH", 443: "HTTPS"}

def now():
    return datetime.datetime.now().strftime("%H:%M:%S")

def add_log(msg):
    entry = f"[{now()}] {msg}"
    with lock:
        logs.append(entry)
        if len(logs) > 300:
            logs.pop(0)
    print(entry)

def _port_service(sport, dport, proto_hint="tcp"):
    port = dport if isinstance(dport, int) else (sport if isinstance(sport, int) else None)
    if port is None:
        return "-"
    
    name = PORT_SERVICES.get(port)
    if name:
        return name
        
    try:
        sysname = socket.getservbyport(port, proto_hint)
        return sysname
    except Exception:
        return "-"

def pkt_has_layer(pkt, layer_obj, layer_name=None):
    try:
        if layer_obj is not None:
            return pkt.haslayer(layer_obj)
        if layer_name:
            return pkt.haslayer(layer_name)
    except Exception:
        pass
    return False

def start_sniffing():
    if sniff is None:
        add_log("Scapy not available.")
        return

    IP = getattr(SCAPY, "IP", None)
    TCP = getattr(SCAPY, "TCP", None)
    UDP = getattr(SCAPY, "UDP", None)
    ICMP = getattr(SCAPY, "ICMP", None)

    def handler(pkt):
        try:
            if not pkt_has_layer(pkt, IP, "IP"):
                return

            sport = None
            dport = None
            proto = "Unknown"

            if pkt_has_layer(pkt, TCP, "TCP"):
                proto = "TCP"
                try:
                    sport = int(pkt[TCP].sport)
                    dport = int(pkt[TCP].dport)
                except:
                    pass
            elif pkt_has_layer(pkt, UDP, "UDP"):
                proto = "UDP"
                try:
                    sport = int(pkt[UDP].sport)
                    dport = int(pkt[UDP].dport)
                except:
                    pass
            elif pkt_has_layer(pkt, ICMP, "ICMP"):
                proto = "ICMP"
            else:
                return

            src_ip = pkt[IP].src if IP is not None else ""
            dst_ip = pkt[IP].dst if IP is not None else ""
            
            if proto == "ICMP":
                service = "ICMP"
            else:
                hint = "tcp" if proto == "TCP" else "udp"
                service = _port_service(sport, dport, proto_hint=hint)

            size = len(pkt)

            rec = {
                "Time": now(),
                "Source IP": src_ip,
                "Source Port": sport,
                "Destination IP": dst_ip,
                "Destination Port": dport,
                "Protocol": proto,
                "Packet Size": size,
                "Service": service
            }

            with lock:
                if monitoring:
                    packets.append(rec)
                    if len(packets) > 1000:
                        packets.pop(0)
        except Exception as e:
            add_log("Error: " + str(e))

    try:
        sniff(prn=handler, store=False, stop_filter=lambda x: not monitoring)
    except Exception as e:
        add_log("Sniff error: " + str(e))

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/start", methods=["POST"])
def start():
    global monitoring, packets, sniff_thread
    with lock:
        monitoring = True
        packets = []
    add_log("Monitoring started.")
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()
    return jsonify({"status": "started"})

@app.route("/stop", methods=["POST"])
def stop():
    global monitoring
    with lock:
        monitoring = False
        total = len(packets)
    add_log(f"Monitoring stopped. Packets: {total}")
    return jsonify({"status": "stopped"})

@app.route("/packets")
def get_packets():
    with lock:
        return jsonify({"packets": list(packets)})

@app.route("/stats")
def get_stats():
    with lock:
        total = len(packets)
        avg_size = round(sum(p["Packet Size"] for p in packets) / total, 1) if total else 0
        proto_count = {}
        for p in packets:
            proto_count[p["Protocol"]] = proto_count.get(p["Protocol"], 0) + 1
        return jsonify({"total": total, "avg_size": avg_size, "proto_count": proto_count})

@app.route("/logs")
def get_logs():
    with lock:
        return jsonify({"logs": list(logs)})

app.run(debug=True, port=5000, threaded=True)