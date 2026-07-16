import sqlite3
import os

DB_NAME = "packets.db"

def get_connection(db_path=DB_NAME):
    """
    Establishes and returns a connection to the SQLite database.
    """
    return sqlite3.connect(db_path)

def init_db(db_path=DB_NAME):
    """
    Initializes the database by creating the packets and alerts tables if they don't exist.
    Also enables WAL journal mode for efficient write throughput.
    """
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL NOT NULL,
        src_ip TEXT NOT NULL,
        dst_ip TEXT NOT NULL,
        src_port INTEGER,
        dst_port INTEGER,
        protocol TEXT NOT NULL,
        size INTEGER NOT NULL
    );
    """
    create_alerts_table_sql = """
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        ip TEXT NOT NULL,
        detail TEXT NOT NULL,
        timestamp TEXT NOT NULL
    );
    """
    conn = None
    try:
        conn = get_connection(db_path)
        # Enable Write-Ahead Logging (WAL) for high performance concurrent writes
        conn.execute("PRAGMA journal_mode=WAL;")
        cursor = conn.cursor()
        cursor.execute(create_table_sql)
        cursor.execute(create_alerts_table_sql)
        conn.commit()
        print(f"Database initialized successfully at: {os.path.abspath(db_path)}")
    except sqlite3.Error as e:
        print(f"Error initializing SQLite database: {e}")
        raise
    finally:
        if conn:
            conn.close()

def log_alert(alert, conn=None, db_path=DB_NAME):
    """
    Logs an anomaly alert in the database alerts table.
    """
    sql = """
    INSERT INTO alerts (type, ip, detail, timestamp)
    VALUES (?, ?, ?, ?)
    """
    values = (
        alert["type"],
        alert["ip"],
        alert["detail"],
        alert["timestamp"]
    )
    
    if conn:
        cursor = conn.cursor()
        cursor.execute(sql, values)
        conn.commit()
    else:
        c = None
        try:
            c = get_connection(db_path)
            cursor = c.cursor()
            cursor.execute(sql, values)
            c.commit()
        except sqlite3.Error as e:
            print(f"Error logging alert: {e}")
        finally:
            if c:
                c.close()



def insert_packet(packet_data, conn=None, db_path=DB_NAME):
    """
    Inserts one parsed packet row into the packets table.
    Can reuse an existing connection `conn` for efficiency.
    """
    sql = """
    INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, size)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """
    values = (
        packet_data["timestamp"],
        packet_data["src_ip"],
        packet_data["dst_ip"],
        packet_data["src_port"],
        packet_data["dst_port"],
        packet_data["protocol"],
        packet_data["size"]
    )
    
    if conn:
        cursor = conn.cursor()
        cursor.execute(sql, values)
        conn.commit()
    else:
        c = None
        try:
            c = get_connection(db_path)
            cursor = c.cursor()
            cursor.execute(sql, values)
            c.commit()
        except sqlite3.Error as e:
            print(f"Error inserting packet: {e}")
        finally:
            if c:
                c.close()

def get_recent_packets(limit=100, db_path=DB_NAME):
    """
    Fetches the most recent packets from the database.
    """
    sql = """
    SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, size
    FROM packets
    ORDER BY timestamp DESC, id DESC
    LIMIT ?
    """
    conn = None
    try:
        conn = get_connection(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(sql, (limit,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    except sqlite3.Error as e:
        print(f"Error fetching recent packets: {e}")
        return []
    finally:
        if conn:
            conn.close()

def get_top_talkers(limit=10, db_path=DB_NAME):
    """
    Returns the source IPs with the highest total traffic (sum of packet sizes),
    grouped by src_ip.
    """
    sql = """
    SELECT src_ip, SUM(size) as total_size, COUNT(id) as packet_count
    FROM packets
    GROUP BY src_ip
    ORDER BY total_size DESC
    LIMIT ?
    """
    conn = None
    try:
        conn = get_connection(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(sql, (limit,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    except sqlite3.Error as e:
        print(f"Error fetching top talkers: {e}")
        return []
    finally:
        if conn:
            conn.close()

def get_protocol_breakdown(db_path=DB_NAME):
    """
    Returns the count of packets grouped by protocol.
    """
    sql = """
    SELECT protocol, COUNT(id) as count
    FROM packets
    GROUP BY protocol
    ORDER BY count DESC
    """
    conn = None
    try:
        conn = get_connection(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(sql)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    except sqlite3.Error as e:
        print(f"Error fetching protocol breakdown: {e}")
        return []
    finally:
        if conn:
            conn.close()

def get_alerts(limit=100, db_path=DB_NAME):
    """
    Fetches the most recent alerts from the database.
    """
    sql = """
    SELECT id, type, ip, detail, timestamp
    FROM alerts
    ORDER BY id DESC
    LIMIT ?
    """
    conn = None
    try:
        conn = get_connection(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(sql, (limit,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    except sqlite3.Error as e:
        print(f"Error fetching alerts: {e}")
        return []
    finally:
        if conn:
            conn.close()

def get_bandwidth_timeline(db_path=DB_NAME):
    """
    Returns total bytes captured per 10-second interval for the last 5 minutes (300 seconds).
    Pads missing intervals with 0 bytes.
    """
    import time
    import datetime
    
    now = time.time()
    start_time = now - 300.0
    
    # Align start_time to a multiple of 10s
    start_time = float(int(start_time / 10) * 10)
    
    sql = """
    SELECT 
        CAST((timestamp - ?) / 10 AS INTEGER) * 10 + ? AS interval_start,
        SUM(size) AS total_bytes
    FROM packets
    WHERE timestamp >= ?
    GROUP BY interval_start
    ORDER BY interval_start ASC
    """
    
    conn = None
    try:
        conn = get_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(sql, (start_time, start_time, start_time))
        rows = cursor.fetchall()
        
        # Convert rows to a dictionary of {interval_start: total_bytes}
        db_timeline = {int(row[0]): row[1] for row in rows}
        
        # Fill in the 30 intervals (every 10s for 5 mins)
        timeline = []
        for i in range(30):
            t_start = int(start_time + i * 10)
            dt_str = datetime.datetime.fromtimestamp(t_start).strftime('%H:%M:%S')
            timeline.append({
                "timestamp": t_start,
                "time_label": dt_str,
                "bytes": db_timeline.get(t_start, 0)
            })
        return timeline
    except sqlite3.Error as e:
        print(f"Error fetching bandwidth timeline: {e}")
        return []
    finally:
        if conn:
            conn.close()



