from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import netwatch.database as db

app = FastAPI(
    title="Netwatch API",
    description="Backend API endpoints for Network Traffic Analyzer stats and alerts.",
    version="1.0.0"
)

# Enable CORS for localhost:3000 and any standard frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/stats/top-talkers")
def stats_top_talkers(limit: int = 10):
    """
    Returns top talker source IPs by aggregate traffic size.
    """
    return db.get_top_talkers(limit=limit, db_path=db.DB_NAME)

@app.get("/stats/protocol-breakdown")
def stats_protocol_breakdown():
    """
    Returns packet counts grouped by protocol.
    """
    return db.get_protocol_breakdown(db_path=db.DB_NAME)

@app.get("/packets/recent")
def packets_recent(limit: int = 100):
    """
    Returns the most recent N packets captured.
    """
    return db.get_recent_packets(limit=limit, db_path=db.DB_NAME)

@app.get("/alerts")
def alerts(limit: int = 100):
    """
    Returns recent security anomaly alerts.
    """
    return db.get_alerts(limit=limit, db_path=db.DB_NAME)

@app.get("/stats/bandwidth-timeline")
def stats_bandwidth_timeline():
    """
    Returns aggregate packet sizes in 10-second intervals for the last 5 minutes.
    """
    return db.get_bandwidth_timeline(db_path=db.DB_NAME)
