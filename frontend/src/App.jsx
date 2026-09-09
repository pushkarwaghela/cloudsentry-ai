import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import StatsBar from './components/StatsBar';
import AlertQueue from './components/AlertQueue';
import InvestigationDrawer from './components/InvestigationDrawer';
import KQLConsole from './components/KQLConsole';
import CSPMPanel from './components/CSPMPanel';

const API_BASE = 'http://localhost:8000/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('alerts');
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  const [alertDetail, setAlertDetail] = useState(null);
  const [cspmData, setCspmData] = useState(null);
  const [kqlResults, setKqlResults] = useState(null);
  const [isSimulating, setIsSimulating] = useState(false);
  const [isKQLRunning, setIsKQLRunning] = useState(false);
  const [notification, setNotification] = useState(null);

  // Show temporary toast notification
  const showToast = (msg, type = 'info') => {
    setNotification({ msg, type });
    setTimeout(() => setNotification(null), 4000);
  };

  // Fetch Stats & Alerts
  const fetchData = async () => {
    try {
      const [resStats, resAlerts, resCspm] = await Promise.all([
        fetch(`${API_BASE}/stats`).then((r) => r.json()),
        fetch(`${API_BASE}/alerts`).then((r) => r.json()),
        fetch(`${API_BASE}/cspm`).then((r) => r.json()),
      ]);
      setStats(resStats);
      setAlerts(resAlerts);
      setCspmData(resCspm);
    } catch (err) {
      console.warn('Backend API connection offline or starting. Check backend port 8000.', err);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000);
    return () => clearInterval(interval);
  }, []);

  // Fetch Alert Detail when selected
  const handleSelectAlert = async (eventId) => {
    setSelectedAlertId(eventId);
    try {
      const res = await fetch(`${API_BASE}/alerts/${eventId}`);
      if (res.ok) {
        const detail = await res.json();
        setAlertDetail(detail);
      }
    } catch (err) {
      console.error('Failed to load alert detail:', err);
    }
  };

  // Update Status
  const handleUpdateStatus = async (eventId, newStatus) => {
    try {
      const res = await fetch(`${API_BASE}/alerts/${eventId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus }),
      });
      if (res.ok) {
        showToast(`Incident marked as ${newStatus}`, 'success');
        setAlerts((prev) =>
          prev.map((a) => (a.event_id === eventId ? { ...a, status: newStatus } : a))
        );
        if (alertDetail && alertDetail.event.event_id === eventId) {
          setAlertDetail((prev) => ({ ...prev, status: newStatus }));
        }
      }
    } catch (e) {
      showToast('Error updating status', 'error');
    }
  };

  // Execute KQL
  const handleRunKQL = async (query) => {
    setIsKQLRunning(true);
    try {
      const res = await fetch(`${API_BASE}/query/kql`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query }),
      });
      if (res.ok) {
        const data = await res.json();
        setKqlResults(data);
      } else {
        showToast('KQL query failed', 'error');
      }
    } catch (e) {
      showToast('Network error executing KQL', 'error');
    } finally {
      setIsKQLRunning(false);
    }
  };

  // Trigger Live Threat Simulation
  const handleSimulate = async (scenario) => {
    setIsSimulating(true);
    try {
      const res = await fetch(`${API_BASE}/simulate/${scenario}`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        showToast(`Injected attack: ${data.scenario} (${data.alerts_generated} alert generated)`, 'warning');
        await fetchData();
        if (data.alerts && data.alerts.length > 0) {
          handleSelectAlert(data.alerts[0].event_id);
        }
      }
    } catch (err) {
      showToast('Simulation failed. Ensure backend is running.', 'error');
    } finally {
      setIsSimulating(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      
      {/* Toast Notification */}
      {notification && (
        <div style={{
          position: 'fixed',
          bottom: '1.5rem',
          right: '1.5rem',
          zIndex: 200,
          background: notification.type === 'error' ? '#ef4444' : notification.type === 'warning' ? '#f97316' : '#0284c7',
          color: '#ffffff',
          padding: '0.75rem 1.25rem',
          borderRadius: '0.5rem',
          boxShadow: '0 10px 30px rgba(0, 0, 0, 0.5)',
          fontSize: '0.85rem',
          fontWeight: 600,
        }}>
          {notification.msg}
        </div>
      )}

      {/* Navigation */}
      <Navbar
        stats={stats}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onSimulate={handleSimulate}
        onRefresh={fetchData}
        isSimulating={isSimulating}
      />

      {/* Main Workspace */}
      <main className="soc-container" style={{ flex: 1 }}>
        
        {/* Metric Bar */}
        <StatsBar stats={stats} />

        {/* Tab 1: Alert Queue */}
        {activeTab === 'alerts' && (
          <AlertQueue
            alerts={alerts}
            onSelectAlert={handleSelectAlert}
            selectedAlertId={selectedAlertId}
          />
        )}

        {/* Tab 2: KQL Console */}
        {activeTab === 'kql' && (
          <KQLConsole
            onRunKQL={handleRunKQL}
            kqlResults={kqlResults}
            isRunning={isKQLRunning}
          />
        )}

        {/* Tab 3: CSPM Posture */}
        {activeTab === 'cspm' && (
          <CSPMPanel cspmData={cspmData} />
        )}

      </main>

      {/* Slide-out Deep Dive Investigation Drawer */}
      {selectedAlertId && alertDetail && (
        <InvestigationDrawer
          alertDetail={alertDetail}
          onClose={() => {
            setSelectedAlertId(null);
            setAlertDetail(null);
          }}
          onUpdateStatus={handleUpdateStatus}
        />
      )}

      {/* Footer */}
      <footer style={{ borderTop: '1px solid var(--border-subtle)', padding: '1rem 2rem', fontSize: '0.75rem', color: 'var(--text-muted)', textAlign: 'center' }}>
        CloudSentry AI • Portfolio Project for SOC Analyst & Security Engineering Roles • Open Cybersecurity Schema Framework (OCSF)
      </footer>

    </div>
  );
}
