import React, { useState } from 'react';
import { 
  AlertTriangle, 
  Search, 
  Filter, 
  ChevronRight, 
  ExternalLink, 
  ShieldAlert, 
  ShieldCheck, 
  Clock, 
  User, 
  Radio 
} from 'lucide-react';

export default function AlertQueue({ alerts, onSelectAlert, selectedAlertId }) {
  const [cloudFilter, setCloudFilter] = useState('all');
  const [sevFilter, setSevFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  // Filtering
  const filteredAlerts = alerts.filter((a) => {
    if (cloudFilter !== 'all' && a.cloud_provider !== cloudFilter) return false;
    if (sevFilter !== 'all' && a.severity.toLowerCase() !== sevFilter.toLowerCase()) return false;
    if (statusFilter !== 'all' && a.status.toLowerCase() !== statusFilter.toLowerCase()) return false;
    if (searchTerm) {
      const s = searchTerm.toLowerCase();
      const matchTitle = (a.incident_title || '').toLowerCase().includes(s);
      const matchActor = (a.actor || '').toLowerCase().includes(s);
      const matchAction = (a.action || '').toLowerCase().includes(s);
      if (!matchTitle && !matchActor && !matchAction) return false;
    }
    return true;
  });

  const getSeverityBadgeClass = (sev) => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      case 'LOW': return 'badge-low';
      default: return 'badge-info';
    }
  };

  const getStatusBadge = (status) => {
    const s = (status || 'NEW').toUpperCase();
    let bg = 'rgba(56, 189, 248, 0.1)';
    let color = 'var(--accent-cyan)';
    let border = '1px solid rgba(56, 189, 248, 0.3)';

    if (s === 'INVESTIGATING') {
      bg = 'rgba(234, 179, 8, 0.15)';
      color = '#facc15';
      border = '1px solid rgba(234, 179, 8, 0.4)';
    } else if (s === 'CONTAINED' || s === 'RESOLVED') {
      bg = 'rgba(16, 185, 129, 0.15)';
      color = '#34d399';
      border = '1px solid rgba(16, 185, 129, 0.4)';
    }

    return (
      <span style={{ 
        padding: '0.2rem 0.5rem', 
        borderRadius: '0.35rem', 
        fontSize: '0.7rem', 
        fontWeight: 700, 
        background: bg, 
        color: color, 
        border: border,
        textTransform: 'uppercase' 
      }}>
        {s}
      </span>
    );
  };

  return (
    <div className="soc-card" style={{ padding: '1.25rem' }}>
      
      {/* Filters & Search Header */}
      <div style={{ 
        display: 'flex', 
        flexWrap: 'wrap', 
        gap: '1rem', 
        alignItems: 'center', 
        justifyContent: 'space-between', 
        paddingBottom: '1.25rem', 
        borderBottom: '1px solid var(--border-subtle)',
        marginBottom: '1rem'
      }}>
        
        {/* Left: Filter Pills */}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'center' }}>
          
          {/* Cloud Provider Pills */}
          <div style={{ display: 'flex', background: 'var(--bg-base)', padding: '0.2rem', borderRadius: '0.4rem', border: '1px solid var(--border-subtle)' }}>
            {['all', 'aws', 'azure'].map((p) => (
              <button
                key={p}
                onClick={() => setCloudFilter(p)}
                style={{
                  padding: '0.3rem 0.75rem',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  borderRadius: '0.3rem',
                  border: 'none',
                  cursor: 'pointer',
                  background: cloudFilter === p ? 'var(--bg-surface-elevated)' : 'transparent',
                  color: cloudFilter === p ? 'var(--text-primary)' : 'var(--text-muted)',
                  textTransform: 'uppercase'
                }}
              >
                {p === 'all' ? 'All Clouds' : p}
              </button>
            ))}
          </div>

          {/* Severity Pills */}
          <div style={{ display: 'flex', background: 'var(--bg-base)', padding: '0.2rem', borderRadius: '0.4rem', border: '1px solid var(--border-subtle)' }}>
            {['all', 'critical', 'high', 'medium'].map((s) => (
              <button
                key={s}
                onClick={() => setSevFilter(s)}
                style={{
                  padding: '0.3rem 0.65rem',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  borderRadius: '0.3rem',
                  border: 'none',
                  cursor: 'pointer',
                  background: sevFilter === s ? 'var(--bg-surface-elevated)' : 'transparent',
                  color: sevFilter === s ? 'var(--text-primary)' : 'var(--text-muted)',
                  textTransform: 'capitalize'
                }}
              >
                {s}
              </button>
            ))}
          </div>

          {/* Status Pills */}
          <div style={{ display: 'flex', background: 'var(--bg-base)', padding: '0.2rem', borderRadius: '0.4rem', border: '1px solid var(--border-subtle)' }}>
            {['all', 'new', 'investigating', 'contained'].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                style={{
                  padding: '0.3rem 0.65rem',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  borderRadius: '0.3rem',
                  border: 'none',
                  cursor: 'pointer',
                  background: statusFilter === st ? 'var(--bg-surface-elevated)' : 'transparent',
                  color: statusFilter === st ? 'var(--text-primary)' : 'var(--text-muted)',
                  textTransform: 'capitalize'
                }}
              >
                {st}
              </button>
            ))}
          </div>

        </div>

        {/* Right: Search Box */}
        <div style={{ position: 'relative', width: '280px' }}>
          <Search size={15} style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            type="text"
            placeholder="Search incident, user, action..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              width: '100%',
              padding: '0.45rem 0.75rem 0.45rem 2.2rem',
              background: 'var(--bg-base)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '0.4rem',
              color: 'var(--text-primary)',
              fontSize: '0.8rem',
              outline: 'none'
            }}
            onFocus={(e) => e.target.style.borderColor = 'var(--accent-cyan)'}
            onBlur={(e) => e.target.style.borderColor = 'var(--border-subtle)'}
          />
        </div>

      </div>

      {/* Alert Table */}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
          <thead>
            <tr style={{ color: 'var(--text-muted)', borderBottom: '1px solid var(--border-subtle)', textTransform: 'uppercase', fontSize: '0.7rem', letterSpacing: '0.04em' }}>
              <th style={{ padding: '0.75rem 1rem' }}>Risk Score</th>
              <th style={{ padding: '0.75rem 1rem' }}>Severity</th>
              <th style={{ padding: '0.75rem 1rem' }}>Cloud</th>
              <th style={{ padding: '0.75rem 1rem' }}>Incident Title & Action</th>
              <th style={{ padding: '0.75rem 1rem' }}>MITRE ATT&CK</th>
              <th style={{ padding: '0.75rem 1rem' }}>Affected Identity</th>
              <th style={{ padding: '0.75rem 1rem' }}>Status</th>
              <th style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>Investigation</th>
            </tr>
          </thead>
          <tbody>
            {filteredAlerts.length === 0 ? (
              <tr>
                <td colSpan={8} style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  No security incidents match the current filter criteria.
                </td>
              </tr>
            ) : (
              filteredAlerts.map((alert) => {
                const isSelected = alert.event_id === selectedAlertId;
                const isCrit = alert.severity.toUpperCase() === 'CRITICAL';

                return (
                  <tr 
                    key={alert.event_id}
                    onClick={() => onSelectAlert(alert.event_id)}
                    style={{ 
                      borderBottom: '1px solid var(--border-subtle)',
                      background: isSelected ? 'var(--bg-surface-elevated)' : 'transparent',
                      cursor: 'pointer',
                      transition: 'background 0.15s ease'
                    }}
                    onMouseEnter={(e) => {
                      if (!isSelected) e.currentTarget.style.background = 'var(--bg-surface-hover)';
                    }}
                    onMouseLeave={(e) => {
                      if (!isSelected) e.currentTarget.style.background = 'transparent';
                    }}
                  >
                    
                    {/* Risk Score Pill */}
                    <td style={{ padding: '0.85rem 1rem', whiteSpace: 'nowrap' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <div style={{ 
                          width: '36px', 
                          height: '36px', 
                          borderRadius: '50%', 
                          background: alert.risk_score >= 80 ? 'rgba(239, 68, 68, 0.2)' : 'rgba(249, 115, 22, 0.2)',
                          color: alert.risk_score >= 80 ? '#f87171' : '#fb923c',
                          border: alert.risk_score >= 80 ? '2px solid rgba(239, 68, 68, 0.6)' : '2px solid rgba(249, 115, 22, 0.5)',
                          display: 'flex', 
                          alignItems: 'center', 
                          justifyContent: 'center',
                          fontWeight: 800,
                          fontSize: '0.75rem'
                        }}>
                          {Math.round(alert.risk_score)}
                        </div>
                        <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                          AE: {alert.anomaly_score}
                        </div>
                      </div>
                    </td>

                    {/* Severity Badge */}
                    <td style={{ padding: '0.85rem 1rem', whiteSpace: 'nowrap' }}>
                      <span className={`soc-badge ${getSeverityBadgeClass(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </td>

                    {/* Cloud Provider */}
                    <td style={{ padding: '0.85rem 1rem', whiteSpace: 'nowrap' }}>
                      <span className={`soc-badge ${alert.cloud_provider === 'aws' ? 'badge-aws' : 'badge-azure'}`}>
                        {alert.cloud_provider}
                      </span>
                    </td>

                    {/* Title & Action */}
                    <td style={{ padding: '0.85rem 1rem', maxWidth: '340px' }}>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.2rem', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {alert.incident_title}
                      </div>
                      <div className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)' }}>
                        {alert.action}
                      </div>
                    </td>

                    {/* MITRE ATT&CK */}
                    <td style={{ padding: '0.85rem 1rem', maxWidth: '220px' }}>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }}>
                        {alert.mitre_techniques && alert.mitre_techniques.slice(0, 1).map((t, idx) => (
                          <span key={idx} style={{ 
                            background: 'rgba(99, 102, 241, 0.15)', 
                            color: '#a5b4fc', 
                            padding: '0.15rem 0.45rem', 
                            borderRadius: '0.3rem', 
                            fontSize: '0.68rem',
                            fontWeight: 600,
                            border: '1px solid rgba(99, 102, 241, 0.3)',
                            whiteSpace: 'nowrap',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            maxWidth: '180px'
                          }}>
                            {t}
                          </span>
                        ))}
                      </div>
                    </td>

                    {/* Affected Identity */}
                    <td style={{ padding: '0.85rem 1rem', whiteSpace: 'nowrap' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--text-primary)', fontWeight: 500 }}>
                        <User size={13} color="var(--text-muted)" />
                        {alert.actor}
                      </div>
                      <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginLeft: '1.2rem' }}>
                        {alert.actor_type}
                      </div>
                    </td>

                    {/* Status Badge */}
                    <td style={{ padding: '0.85rem 1rem', whiteSpace: 'nowrap' }}>
                      {getStatusBadge(alert.status)}
                    </td>

                    {/* Action Button */}
                    <td style={{ padding: '0.85rem 1rem', textAlign: 'right', whiteSpace: 'nowrap' }}>
                      <button 
                        className="soc-btn soc-btn-secondary"
                        style={{ padding: '0.35rem 0.65rem', fontSize: '0.75rem' }}
                      >
                        Triage <ChevronRight size={14} />
                      </button>
                    </td>

                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

    </div>
  );
}
