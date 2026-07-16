import datetime
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP
from netwatch.database import insert_packet, get_connection, log_alert, get_recent_packets
from netwatch.anomaly import detect_port_scan, detect_traffic_spike, detect_suspicious_ports

def parse_packet(packet):
    """
    Parses a single scapy packet. If it doesn't contain an IP layer, it returns None.
    Otherwise, it returns a dictionary with extracted packet details.
    """
    if IP not in packet:
        return None

    ip_layer = packet[IP]
    
    # Identify protocol
    proto_num = ip_layer.proto
    protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
    protocol = protocol_map.get(proto_num, f"OTHER ({proto_num})")
    
    # Extract ports if applicable
    src_port = None
    dst_port = None
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        
    packet_data = {
        "timestamp": float(packet.time),
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "size": len(packet)
    }
    
    return packet_data

def start_capture(interface=None, db_path="packets.db"):
    """
    Starts sniffing live packets on the specified network interface,
    inserts them into the DB, and runs rule-based anomaly detection.
    """
    if interface:
        print(f"Starting packet capture on interface: {interface}...")
    else:
        print("Starting packet capture on default interface...")
        
    print("Press Ctrl+C to stop.")
    
    conn = None
    try:
        conn = get_connection(db_path)
        
        # Tracking variables for batch-based triggers
        state = {
            "packet_count": 0,
            "last_check_time": time.time()
        }
        
        # Define inline packet handler callback to access conn closure and tracking state
        def packet_handler(packet):
            parsed = parse_packet(packet)
            if parsed:
                # 1. Insert into SQLite database
                insert_packet(parsed, conn=conn)
                state["packet_count"] += 1
                
                # 2. Print live packet info to console
                dt = datetime.datetime.fromtimestamp(parsed["timestamp"]).strftime('%Y-%m-%d %H:%M:%S.%f')
                ports_info = f" {parsed['src_port']} -> {parsed['dst_port']}" if parsed['src_port'] else ""
                print(f"[{dt}] {parsed['protocol']} | {parsed['src_ip']}{ports_info} -> {parsed['dst_ip']} | Size: {parsed['size']} B")
                
                # 3. Check for immediate suspicious port anomalies
                port_alerts = detect_suspicious_ports(parsed)
                for alert in port_alerts:
                    log_alert(alert, conn=conn)
                    print(f"\n>>> [ALERT] SUSPICIOUS_PORT: {alert['detail']} (IP: {alert['ip']}) <<<\n")
                
                # 4. Trigger batch-based checks (every 50 packets or 10 seconds)
                now = time.time()
                if state["packet_count"] % 50 == 0 or (now - state["last_check_time"]) >= 10.0:
                    state["last_check_time"] = now
                    
                    # Fetch recent packets from DB to check windows
                    recent = get_recent_packets(limit=500, db_path=db_path)
                    
                    # Run Port Scan check
                    scan_alerts = detect_port_scan(recent)
                    for alert in scan_alerts:
                        log_alert(alert, conn=conn)
                        print(f"\n>>> [ALERT] PORT_SCAN: {alert['detail']} (IP: {alert['ip']}) <<<\n")
                        
                    # Run Traffic Spike check (using default 5MB threshold)
                    spike_alerts = detect_traffic_spike(recent)
                    for alert in spike_alerts:
                        log_alert(alert, conn=conn)
                        print(f"\n>>> [ALERT] TRAFFIC_SPIKE: {alert['detail']} (IP: {alert['ip']}) <<<\n")

        # sniff will run indefinitely unless stopped
        sniff(iface=interface, prn=packet_handler, store=False)
        
    except PermissionError:
        print("\n[ERROR] Permission denied: Packet capture requires Administrator/root privileges.")
        print("Please run this command from an elevated shell (run as Administrator/sudo).")
    except OSError as e:
        print(f"\n[ERROR] OS Error during packet capture: {e}")
        print("This could be due to a missing capture driver (Npcap on Windows) or an invalid interface name.")
    except Exception as e:
        print(f"\n[ERROR] Unexpected error during packet capture: {e}")
    finally:
        if conn:
            conn.close()
            print("Database connection closed.")


