import React from 'react';
import { Activity, AlertOctagon, ShieldCheck, Database, Layers } from 'lucide-react';

export default function StatsBar({ stats }) {
  if (!stats) return null;

  const awsPct = stats.total_events > 0 ? Math.round((stats.aws_event_count / stats.total_events) * 100) : 50;
  const azurePct = 100 - awsPct;

  return (
    <div style={{ 
      display: 'grid', 
      gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', 
      gap: '1rem', 
      marginBottom: '1.5rem' 
    }}>
      
      {/* Total Telemetry */}
      <div className="soc-card" style={{ padding: '1rem 1.25rem', display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <div style={{ background: 'rgba(56, 189, 248, 0.1)', padding: '0.75rem', borderRadius: '0.5rem', color: 'var(--accent-cyan)' }}>
          <Database size={22} />
        </div>
        <div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
            Normalized Telemetry
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--text-primary)' }}>
            {stats.total_events.toLocaleString()} <span style={{ fontSize: '0.75rem', fontWeight: 500, color: 'var(--text-muted)' }}>OCSF events</span>
          </div>
        </div>
      </div>

      {/* Active Alerts */}
      <div className="soc-card" style={{ padding: '1rem 1.25rem', display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <div style={{ background: 'rgba(234, 179, 8, 0.1)', padding: '0.75rem', borderRadius: '0.5rem', color: 'var(--sev-medium)' }}>
          <Activity size={22} />
        </div>
        <div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
            Triaged Incidents
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--text-primary)' }}>
            {stats.total_alerts} <span style={{ fontSize: '0.75rem', fontWeight: 500, color: 'var(--text-muted)' }}>in queue</span>
          </div>
        </div>
      </div>

      {/* Critical Threats */}
      <div className="soc-card" style={{ padding: '1rem 1.25rem', display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <div style={{ background: 'rgba(239, 68, 68, 0.15)', padding: '0.75rem', borderRadius: '0.5rem', color: 'var(--sev-critical)' }}>
          <AlertOctagon size={22} className={stats.critical_alerts > 0 ? "animate-pulse" : ""} />
        </div>
        <div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
            Critical Severity Threats
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#f87171' }}>
            {stats.critical_alerts} <span style={{ fontSize: '0.75rem', fontWeight: 500, color: 'var(--text-muted)' }}>({stats.high_alerts} High)</span>
          </div>
        </div>
      </div>

      {/* Multi-Cloud Distribution */}
      <div className="soc-card" style={{ padding: '1rem 1.25rem', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '0.4rem' }}>
          <span>AWS ({awsPct}%)</span>
          <span>Azure ({azurePct}%)</span>
        </div>
        <div style={{ width: '100%', height: '8px', background: 'var(--bg-surface-elevated)', borderRadius: '4px', overflow: 'hidden', display: 'flex' }}>
          <div style={{ width: `${awsPct}%`, background: '#ff9900', transition: 'width 0.3s' }} title={`AWS: ${stats.aws_event_count} events`} />
          <div style={{ width: `${azurePct}%`, background: '#0078d4', transition: 'width 0.3s' }} title={`Azure: ${stats.azure_event_count} events`} />
        </div>
        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.35rem', textAlign: 'center' }}>
          Unified Ingestion Pipeline
        </div>
      </div>

      {/* CSPM Compliance Score */}
      <div className="soc-card" style={{ padding: '1rem 1.25rem', display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <div style={{ 
          background: stats.cspm_score >= 80 ? 'rgba(16, 185, 129, 0.1)' : 'rgba(249, 115, 22, 0.1)', 
          padding: '0.75rem', 
          borderRadius: '0.5rem', 
          color: stats.cspm_score >= 80 ? 'var(--status-success)' : 'var(--sev-high)' 
        }}>
          <ShieldCheck size={22} />
        </div>
        <div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
            CIS Benchmark Posture
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, color: stats.cspm_score >= 80 ? 'var(--status-success)' : 'var(--sev-high)' }}>
            {stats.cspm_score}% <span style={{ fontSize: '0.75rem', fontWeight: 500, color: 'var(--text-muted)' }}>score</span>
          </div>
        </div>
      </div>

    </div>
  );
}
