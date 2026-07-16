import React, { useState, useEffect } from 'react';
import { 
  ResponsiveContainer, 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip as ChartTooltip, 
  PieChart, 
  Pie, 
  Cell, 
  Legend 
} from 'recharts';
import { 
  ShieldAlert, 
  Activity, 
  Wifi, 
  WifiOff, 
  Server, 
  Radio, 
  AlertOctagon, 
  Network, 
  ArrowUpRight, 
  ListFilter 
} from 'lucide-react';

const API_BASE = 'http://localhost:8000';

// Protocol breakdown color mapping
const PROTO_COLORS = {
  TCP: '#3b82f6',
  UDP: '#10b981',
  ICMP: '#f59e0b'
};
const FALLBACK_COLORS = ['#8b5cf6', '#ec4899', '#06b6d4', '#84cc16'];

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function App() {
  const [timeline, setTimeline] = useState([]);
  const [protocols, setProtocols] = useState([]);
  const [topTalkers, setTopTalkers] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [apiOnline, setApiOnline] = useState(false);

  // Computed dashboard aggregations
  const totalBytes = topTalkers.reduce((acc, curr) => acc + (curr.total_size || 0), 0);
  const totalPackets = protocols.reduce((acc, curr) => acc + (curr.count || 0), 0);
  const activeAlertCount = alerts.length;

  const fetchData = async () => {
    try {
      // Parallel fetches for responsiveness
      const [resTimeline, resProto, resTalkers, resAlerts] = await Promise.all([
        fetch(`${API_BASE}/stats/bandwidth-timeline`),
        fetch(`${API_BASE}/stats/protocol-breakdown`),
        fetch(`${API_BASE}/stats/top-talkers`),
        fetch(`${API_BASE}/alerts`)
      ]);

      if (resTimeline.ok && resProto.ok && resTalkers.ok && resAlerts.ok) {
        const dataTimeline = await resTimeline.json();
        const dataProto = await resProto.json();
        const dataTalkers = await resTalkers.json();
        const dataAlerts = await resAlerts.json();

        setTimeline(dataTimeline);
        setProtocols(dataProto);
        setTopTalkers(dataTalkers);
        setAlerts(dataAlerts);
        setApiOnline(true);
      } else {
        setApiOnline(false);
      }
    } catch (err) {
      setApiOnline(false);
    }
  };

  useEffect(() => {
    // Initial fetch
    fetchData();

    // Poll endpoint data every 3 seconds
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="dashboard-container">
      {/* Header section */}
      <header className="header">
        <h1>
          <Network size={32} />
          Netwatch <span>Traffic Dashboard</span>
        </h1>
        <div className="api-status">
          <span className={`status-dot ${apiOnline ? 'online' : 'offline'}`}></span>
          {apiOnline ? (
            <>
              <Wifi size={16} /> API Online
            </>
          ) : (
            <>
              <WifiOff size={16} style={{ color: '#ef4444' }} /> API Offline
            </>
          )}
        </div>
      </header>

      {/* KPI Cards Row */}
      <section className="kpi-grid">
        <div className="kpi-card">
          <div className="kpi-info">
            <h3>Total Sniffed Volume</h3>
            <p className="value">{formatBytes(totalBytes)}</p>
          </div>
          <div className="kpi-icon success">
            <ArrowUpRight size={24} />
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-info">
            <h3>Packets Captured</h3>
            <p className="value">{totalPackets.toLocaleString()}</p>
          </div>
          <div className="kpi-icon">
            <Activity size={24} />
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-info">
            <h3>Security Alerts</h3>
            <p className="value">{activeAlertCount}</p>
          </div>
          <div className="kpi-icon alerts">
            <ShieldAlert size={24} />
          </div>
        </div>
      </section>

      {/* Dashboard Visual Grid */}
      <div className="dashboard-grid">
        {/* Left column: charts and talkers */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Timeline chart */}
          <div className="card">
            <div className="card-header">
              <h2>
                <Activity size={20} style={{ color: '#3b82f6' }} />
                Bandwidth Timeline (Last 5 Mins)
              </h2>
            </div>
            <div className="chart-container">
              {apiOnline && timeline.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timeline} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                    <defs>
                      <linearGradient id="colorBytes" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4}/>
                        <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e1e24" />
                    <XAxis 
                      dataKey="time_label" 
                      stroke="#71717a" 
                      fontSize={11}
                      tickLine={false}
                    />
                    <YAxis 
                      stroke="#71717a" 
                      fontSize={11}
                      tickLine={false}
                      tickFormatter={formatBytes}
                    />
                    <ChartTooltip
                      contentStyle={{
                        backgroundColor: '#0c0c0f',
                        borderColor: '#1e1e24',
                        borderRadius: '8px',
                        color: '#fafafa',
                        fontFamily: 'DM Sans, sans-serif'
                      }}
                      formatter={(value) => [formatBytes(value), 'Volume']}
                    />
                    <Area 
                      type="monotone" 
                      dataKey="bytes" 
                      stroke="#3b82f6" 
                      strokeWidth={2}
                      fillOpacity={1} 
                      fill="url(#colorBytes)" 
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="no-alerts">
                  <Activity size={32} />
                  <p>No bandwidth data available.</p>
                </div>
              )}
            </div>
          </div>

          {/* Top Talkers Table */}
          <div className="card">
            <div className="card-header">
              <h2>
                <Server size={20} style={{ color: '#10b981' }} />
                Top Traffic Talkers (Source IPs)
              </h2>
            </div>
            <div className="table-container">
              {apiOnline && topTalkers.length > 0 ? (
                <table>
                  <thead>
                    <tr>
                      <th>Source IP Address</th>
                      <th>Total Bytes Sent</th>
                      <th>Packet Count</th>
                    </tr>
                  </thead>
                  <tbody>
                    {topTalkers.map((talker, idx) => (
                      <tr key={idx}>
                        <td className="mono" style={{ fontWeight: 500 }}>{talker.src_ip}</td>
                        <td className="mono" style={{ color: '#10b981' }}>{formatBytes(talker.total_size)}</td>
                        <td className="mono">{talker.packet_count.toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="no-alerts" style={{ height: '150px' }}>
                  <Server size={32} />
                  <p>No traffic aggregations found.</p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Right column: Protocol breakdown and Alerts feed */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Protocol Pie Chart */}
          <div className="card">
            <div className="card-header">
              <h2>
                <Radio size={20} style={{ color: '#8b5cf6' }} />
                Protocol Breakdown
              </h2>
            </div>
            <div className="chart-container" style={{ height: '240px' }}>
              {apiOnline && protocols.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={protocols}
                      cx="50%"
                      cy="45%"
                      innerRadius={50}
                      outerRadius={70}
                      paddingAngle={4}
                      dataKey="count"
                      nameKey="protocol"
                    >
                      {protocols.map((entry, index) => {
                        const protoName = entry.protocol.split(' ')[0]; // Handle OTHER (num) names
                        const color = PROTO_COLORS[protoName] || FALLBACK_COLORS[index % FALLBACK_COLORS.length];
                        return <Cell key={`cell-${index}`} fill={color} />;
                      })}
                    </Pie>
                    <ChartTooltip
                      contentStyle={{
                        backgroundColor: '#0c0c0f',
                        borderColor: '#1e1e24',
                        borderRadius: '8px',
                        color: '#fafafa'
                      }}
                      formatter={(value) => [value.toLocaleString() + ' packets', 'Count']}
                    />
                    <Legend 
                      verticalAlign="bottom" 
                      height={36}
                      iconType="circle"
                      iconSize={10}
                      wrapperStyle={{ fontSize: '12px', color: '#fafafa' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="no-alerts" style={{ height: '100%' }}>
                  <Radio size={32} />
                  <p>No protocol data found.</p>
                </div>
              )}
            </div>
          </div>

          {/* Alerts Feed */}
          <div className="card" style={{ flexGrow: 1 }}>
            <div className="card-header">
              <h2>
                <ShieldAlert size={20} style={{ color: '#ef4444' }} />
                Live Anomaly Alerts
              </h2>
            </div>
            <div className="alerts-list">
              {apiOnline && alerts.length > 0 ? (
                alerts.map((alert, idx) => (
                  <div key={idx} className="alert-item">
                    <div className="alert-meta">
                      <span className="alert-type">{alert.type.replace('_', ' ')}</span>
                      <span className="alert-time">
                        {alert.timestamp ? alert.timestamp.split('T')[1].substring(0, 8) : ''}
                      </span>
                    </div>
                    <div className="alert-detail">{alert.detail}</div>
                    <div className="alert-ip">{alert.ip}</div>
                  </div>
                ))
              ) : (
                <div className="no-alerts" style={{ height: '220px' }}>
                  <AlertOctagon size={32} style={{ color: '#71717a' }} />
                  <p>No security anomalies detected.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
