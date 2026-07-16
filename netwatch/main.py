import argparse
import sys
import os
import threading
import uvicorn

# Allow direct script execution by adding parent directory to sys.path
if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netwatch.database import init_db
import netwatch.database
from netwatch.capture import start_capture

def list_interfaces():
    """
    Lists the available network interfaces using Scapy.
    """
    try:
        from scapy.all import conf
        print("\nAvailable Network Interfaces:")
        print(conf.ifaces)
    except Exception as e:
        print(f"Error listing network interfaces: {e}")

def main():
    parser = argparse.ArgumentParser(description="Netwatch: A simple network traffic analyzer.")
    parser.add_argument(
        "-i", "--interface", 
        type=str, 
        default=None, 
        help="Name of the interface to sniff on (e.g. 'Ethernet', 'Wi-Fi'). If not specified, default interface is used."
    )
    parser.add_argument(
        "-l", "--list", 
        action="store_true", 
        help="List all available network interfaces and exit."
    )
    parser.add_argument(
        "-d", "--db", 
        type=str, 
        default="packets.db", 
        help="Path to the SQLite database file where schema is initialized."
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="IP address to run the FastAPI server on (default: 127.0.0.1)."
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to run the FastAPI server on (default: 8000)."
    )
    
    args = parser.parse_args()
    
    if args.list:
        list_interfaces()
        return

    # Initialize the database schema
    try:
        init_db(args.db)
        # Propagate the DB path to the database module singleton
        netwatch.database.DB_NAME = args.db
    except Exception as e:
        print(f"Failed to initialize database: {e}. Exiting.")
        sys.exit(1)

    # Start packet capture in a background daemon thread
    capture_thread = threading.Thread(
        target=start_capture, 
        kwargs={"interface": args.interface, "db_path": args.db}, 
        daemon=True
    )
    capture_thread.start()
    print("Background packet capture thread started.")

    # Start the FastAPI server using Uvicorn in the main thread
    print(f"Starting API server on http://{args.host}:{args.port}...")
    try:
        uvicorn.run("netwatch.api:app", host=args.host, port=args.port, log_level="info")
    except KeyboardInterrupt:
        print("\nShutdown signal received. Stopping Netwatch...")

if __name__ == "__main__":
    main()


