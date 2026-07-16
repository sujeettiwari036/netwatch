import datetime

def detect_port_scan(recent_packets):
    """
    Flags an IP if it hits more than 15 distinct destination ports within a 10-second window.
    """
    if not recent_packets:
        return []
        
    alerts = []
    # Determine the time window (10 seconds from the latest packet timestamp)
    latest_time = max(p["timestamp"] for p in recent_packets)
    window_start = latest_time - 10.0
    
    # Filter packets in the 10s window
    window_packets = [p for p in recent_packets if p["timestamp"] >= window_start]
    
    # Group destination ports by source IP
    ip_ports = {}
    for p in window_packets:
        src = p["src_ip"]
        dst_port = p["dst_port"]
        if dst_port is not None:
            if src not in ip_ports:
                ip_ports[src] = set()
            ip_ports[src].add(dst_port)
            
    # Check threshold (> 15 distinct destination ports)
    for ip, ports in ip_ports.items():
        if len(ports) > 15:
            detail = f"IP {ip} accessed {len(ports)} distinct destination ports within 10 seconds."
            alerts.append({
                "type": "port_scan",
                "ip": ip,
                "detail": detail,
                "timestamp": datetime.datetime.now().isoformat()
            })
            
    return alerts

def detect_traffic_spike(recent_packets, threshold_bytes=5 * 1024 * 1024):
    """
    Flags an IP if total bytes from that IP exceeds threshold_bytes (default 5MB) within 10 seconds.
    """
    if not recent_packets:
        return []
        
    alerts = []
    latest_time = max(p["timestamp"] for p in recent_packets)
    window_start = latest_time - 10.0
    
    # Filter packets in the 10s window
    window_packets = [p for p in recent_packets if p["timestamp"] >= window_start]
    
    # Sum sizes by source IP
    ip_sizes = {}
    for p in window_packets:
        src = p["src_ip"]
        ip_sizes[src] = ip_sizes.get(src, 0) + p["size"]
        
    # Check threshold
    for ip, total_size in ip_sizes.items():
        if total_size > threshold_bytes:
            mb_size = total_size / (1024 * 1024)
            detail = f"IP {ip} sent {mb_size:.2f} MB of traffic within 10 seconds (threshold: {threshold_bytes / (1024 * 1024):.2f} MB)."
            alerts.append({
                "type": "traffic_spike",
                "ip": ip,
                "detail": detail,
                "timestamp": datetime.datetime.now().isoformat()
            })
            
    return alerts

def detect_suspicious_ports(packet):
    """
    Flags if the destination port is in a known list of suspicious ports (e.g. 4444, 6667, 31337).
    """
    suspicious = {4444, 6667, 31337}
    dst_port = packet.get("dst_port")
    
    if dst_port in suspicious:
        detail = f"Suspicious connection attempt to destination port {dst_port}."
        return [{
            "type": "suspicious_port",
            "ip": packet["src_ip"],
            "detail": detail,
            "timestamp": datetime.datetime.now().isoformat()
        }]
    return []
