import React, { useState } from 'react';
import { 
  X, 
  ShieldAlert, 
  ExternalLink, 
  CheckCircle, 
  Copy, 
  Check, 
  Clock, 
  MapPin, 
  Terminal, 
  FileText, 
  Layers, 
  AlertOctagon, 
  Radio 
} from 'lucide-react';

export default function InvestigationDrawer({ 
  alertDetail, 
  onClose, 
  onUpdateStatus 
}) {
  if (!alertDetail) return null;

  const { event, triage, status, raw_log, correlated_events } = alertDetail;
  const [activeSubTab, setActiveSubTab] = useState('triage');
  const [copiedIndex, setCopiedIndex] = useState(null);

  const handleCopy = (command, idx) => {
    navigator.clipboard.writeText(command);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const getSeverityColor = (sev) => {
    switch ((sev || '').toUpperCase()) {
      case 'CRITICAL': return '#f87171';
      case 'HIGH': return '#fb923c';
      case 'MEDIUM': return '#facc15';
      default: return '#60a5fa';
    }
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      right: 0,
      bottom: 0,
      width: '740px',
      maxWidth: '90vw',
      background: 'var(--bg-surface)',
      borderLeft: '1px solid var(--border-prominent)',
      boxShadow: '-10px 0 40px rgba(0, 0, 0, 0.7)',
      zIndex: 100,
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden',
    }}>
      
      {/* Header */}
      <div style={{
        padding: '1.25rem 1.5rem',
        borderBottom: '1px solid var(--border-subtle)',
        background: 'var(--bg-surface-elevated)',
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'space-between',
        gap: '1rem'
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.4rem' }}>
            <span style={{ 
              padding: '0.2rem 0.6rem', 
              borderRadius: '0.35rem', 
              fontSize: '0.72rem', 
              fontWeight: 800, 
              background: 'rgba(239, 68, 68, 0.15)', 
              color: getSeverityColor(event.severity),
              border: `1px solid ${getSeverityColor(event.severity)}40` 
            }}>
              {event.severity}
            </span>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Risk Score: <strong style={{ color: '#ffffff' }}>{event.risk_score}</strong> / 100
            </span>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              AE Loss: <strong style={{ color: 'var(--accent-cyan)' }}>{event.anomaly_score}</strong>
            </span>
          </div>
          <h2 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#ffffff', lineHeight: 1.3 }}>
            {triage ? triage.incident_title : event.action}
          </h2>
        </div>

        {/* Close button */}
        <button 
          onClick={onClose}
          style={{ 
            background: 'transparent', 
            border: 'none', 
            color: 'var(--text-muted)', 
            cursor: 'pointer',
            padding: '0.3rem',
            borderRadius: '0.35rem'
          }}
          onMouseEnter={(e) => e.currentTarget.style.color = '#ffffff'}
          onMouseLeave={(e) => e.currentTarget.style.color = 'var(--text-muted)'}
        >
          <X size={20} />
        </button>
      </div>

      {/* Incident Status Bar */}
      <div style={{ 
        padding: '0.75rem 1.5rem', 
        background: 'var(--bg-base)', 
        borderBottom: '1px solid var(--border-subtle)',
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'space-between' 
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          <span>Current Status:</span>
          <select 
            value={status} 
            onChange={(e) => onUpdateStatus(event.event_id, e.target.value)}
            style={{
              background: 'var(--bg-surface-elevated)',
              color: 'var(--accent-cyan)',
              border: '1px solid var(--border-prominent)',
              borderRadius: '0.35rem',
              padding: '0.25rem 0.6rem',
              fontWeight: 700,
              fontSize: '0.75rem',
              outline: 'none',
              cursor: 'pointer'
            }}
          >
            <option value="NEW">NEW</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="CONTAINED">CONTAINED</option>
            <option value="RESOLVED">RESOLVED</option>
            <option value="DISMISSED">DISMISSED</option>
          </select>
        </div>

        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <Clock size={13} /> {event.timestamp}
        </div>
      </div>

      {/* Drawer Sub-Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border-subtle)', background: 'var(--bg-surface)' }}>
        {[
          { id: 'triage', label: 'AI Incident Triage', icon: ShieldAlert },
          { id: 'timeline', label: `Correlated Timeline (${correlated_events?.length || 0})`, icon: Clock },
          { id: 'ocsf', label: 'OCSF Event', icon: Layers },
          { id: 'raw', label: 'Raw Telemetry', icon: Terminal },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeSubTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveSubTab(tab.id)}
              style={{
                flex: 1,
                padding: '0.75rem 0.5rem',
                fontSize: '0.78rem',
                fontWeight: 600,
                background: isActive ? 'var(--bg-surface-elevated)' : 'transparent',
                color: isActive ? 'var(--accent-cyan)' : 'var(--text-muted)',
                border: 'none',
                borderBottom: isActive ? '2px solid var(--accent-cyan)' : '2px solid transparent',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.4rem'
              }}
            >
              <Icon size={14} />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Drawer Body */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '1.5rem' }}>
        
        {/* TAB 1: AI Incident Triage */}
        {activeSubTab === 'triage' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            
            {/* Executive Summary Card */}
            <div style={{ 
              background: 'rgba(15, 23, 42, 0.6)', 
              border: '1px solid var(--border-prominent)', 
              borderRadius: '0.6rem', 
              padding: '1.25rem' 
            }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.6rem' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--accent-cyan)', letterSpacing: '0.04em' }}>
                  AI Executive Incident Summary
                </span>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                  Inference: {triage.llm_provider} ({triage.inference_time_ms}ms)
                </span>
              </div>
              <p style={{ fontSize: '0.88rem', lineHeight: 1.6, color: '#e2e8f0' }}>
                {triage.executive_summary}
              </p>
              
              <div style={{ marginTop: '0.85rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border-subtle)', display: 'flex', gap: '1rem', fontSize: '0.75rem' }}>
                <span style={{ color: 'var(--text-muted)' }}>
                  Confidence: <strong style={{ color: '#34d399' }}>{Math.round(triage.confidence_score * 100)}%</strong>
                </span>
                <span style={{ color: 'var(--text-muted)' }}>
                  Rationale: <span style={{ color: 'var(--text-secondary)' }}>{triage.confidence_rationale}</span>
                </span>
              </div>
            </div>

            {/* MITRE ATT&CK Matrix Alignment */}
            <div>
              <h3 style={{ fontSize: '0.85rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.6rem' }}>
                MITRE ATT&CK Matrix Mapping
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {triage.mitre_attack && triage.mitre_attack.map((m, idx) => (
                  <div key={idx} style={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    justifyContent: 'space-between', 
                    padding: '0.65rem 0.85rem', 
                    background: 'var(--bg-surface-elevated)', 
                    borderRadius: '0.4rem', 
                    border: '1px solid var(--border-subtle)' 
                  }}>
                    <div>
                      <span style={{ 
                        background: 'rgba(99, 102, 241, 0.2)', 
                        color: '#a5b4fc', 
                        padding: '0.2rem 0.5rem', 
                        borderRadius: '0.3rem', 
                        fontSize: '0.72rem', 
                        fontWeight: 700, 
                        marginRight: '0.6rem' 
                      }}>
                        {m.technique_id}
                      </span>
                      <strong style={{ fontSize: '0.82rem', color: '#ffffff' }}>{m.technique_name}</strong>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>
                        ({m.tactic})
                      </span>
                    </div>
                    {m.reference_url && (
                      <a 
                        href={m.reference_url} 
                        target="_blank" 
                        rel="noreferrer" 
                        style={{ color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '0.25rem', fontSize: '0.75rem', textDecoration: 'none' }}
                      >
                        MITRE <ExternalLink size={12} />
                      </a>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Tactical Containment Playbook */}
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.6rem' }}>
                <h3 style={{ fontSize: '0.85rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                  Tactical Containment Playbook (SOC SOP)
                </h3>
                <span style={{ fontSize: '0.7rem', color: 'var(--status-success)', fontWeight: 600 }}>
                  Ready to Execute
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {triage.containment_playbook && triage.containment_playbook.map((step, idx) => (
                  <div key={idx} style={{ 
                    background: 'var(--bg-base)', 
                    border: '1px solid var(--border-subtle)', 
                    borderRadius: '0.5rem', 
                    padding: '0.85rem' 
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                      <span style={{ fontWeight: 700, fontSize: '0.82rem', color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <span style={{ 
                          width: '20px', 
                          height: '20px', 
                          borderRadius: '50%', 
                          background: 'var(--accent-blue)', 
                          color: '#fff', 
                          display: 'inline-flex', 
                          alignItems: 'center', 
                          justifyContent: 'center', 
                          fontSize: '0.7rem', 
                          fontWeight: 800 
                        }}>
                          {step.order}
                        </span>
                        {step.title}
                      </span>
                      <span className="soc-badge" style={{ fontSize: '0.65rem', background: 'rgba(249, 115, 22, 0.15)', color: '#fb923c' }}>
                        {step.action_type}
                      </span>
                    </div>

                    <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
                      {step.rationale}
                    </p>

                    {step.command && (
                      <div style={{ 
                        position: 'relative', 
                        background: '#040711', 
                        padding: '0.6rem 0.8rem', 
                        borderRadius: '0.35rem', 
                        border: '1px solid var(--border-prominent)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between'
                      }}>
                        <code className="font-mono" style={{ fontSize: '0.72rem', color: '#38bdf8', wordBreak: 'break-all' }}>
                          {step.command}
                        </code>
                        <button
                          onClick={() => handleCopy(step.command, idx)}
                          style={{
                            background: 'var(--bg-surface-elevated)',
                            border: '1px solid var(--border-prominent)',
                            color: copiedIndex === idx ? 'var(--status-success)' : 'var(--text-muted)',
                            borderRadius: '0.3rem',
                            padding: '0.25rem 0.5rem',
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.3rem',
                            fontSize: '0.7rem',
                            marginLeft: '0.5rem'
                          }}
                          title="Copy CLI command"
                        >
                          {copiedIndex === idx ? <Check size={12} /> : <Copy size={12} />}
                          {copiedIndex === idx ? 'Copied' : 'Copy'}
                        </button>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

          </div>
        )}

        {/* TAB 2: Correlated Timeline */}
        {activeSubTab === 'timeline' && (
          <div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
              Correlated activities involving identity <strong style={{ color: '#fff' }}>{event.actor.user_name}</strong> or source IP in the ±60 minute blast radius:
            </p>

            {correlated_events && correlated_events.length > 0 ? (
              <div style={{ position: 'relative', paddingLeft: '1.5rem', borderLeft: '2px solid var(--border-prominent)' }}>
                {correlated_events.map((c, idx) => (
                  <div key={idx} style={{ position: 'relative', marginBottom: '1.25rem' }}>
                    <div style={{ 
                      position: 'absolute', 
                      left: '-1.85rem', 
                      top: '0.2rem', 
                      width: '10px', 
                      height: '10px', 
                      borderRadius: '50%', 
                      background: c.risk_score >= 60 ? 'var(--sev-critical)' : 'var(--accent-blue)' 
                    }} />
                    
                    <div style={{ background: 'var(--bg-surface-elevated)', padding: '0.75rem', borderRadius: '0.4rem', border: '1px solid var(--border-subtle)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                        <span className="font-mono" style={{ fontWeight: 600, color: 'var(--accent-cyan)', fontSize: '0.78rem' }}>
                          {c.action}
                        </span>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                          {c.timestamp}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', gap: '1rem' }}>
                        <span>Actor: <strong style={{ color: '#fff' }}>{c.actor}</strong></span>
                        <span>Cloud: <strong style={{ textTransform: 'uppercase' }}>{c.cloud}</strong></span>
                        <span>Reason: <strong style={{ color: 'var(--status-warning)' }}>{c.correlation_reason}</strong></span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                Zero correlated collateral events detected within blast radius.
              </div>
            )}
          </div>
        )}

        {/* TAB 3: OCSF Unified JSON */}
        {activeSubTab === 'ocsf' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                OCSF v1.2.0 Normalized Schema Payload:
              </span>
              <button 
                onClick={() => handleCopy(JSON.stringify(event, null, 2), 999)}
                className="soc-btn soc-btn-secondary" 
                style={{ fontSize: '0.7rem', padding: '0.2rem 0.5rem' }}
              >
                Copy OCSF JSON
              </button>
            </div>
            <pre className="font-mono" style={{ 
              background: '#040711', 
              padding: '1rem', 
              borderRadius: '0.5rem', 
              border: '1px solid var(--border-prominent)', 
              fontSize: '0.75rem', 
              color: '#38bdf8', 
              overflowX: 'auto',
              maxHeight: '600px'
            }}>
              {JSON.stringify(event, null, 2)}
            </pre>
          </div>
        )}

        {/* TAB 4: Raw Telemetry */}
        {activeSubTab === 'raw' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Original Native Cloud Audit Payload:
              </span>
              <button 
                onClick={() => handleCopy(JSON.stringify(raw_log, null, 2), 998)}
                className="soc-btn soc-btn-secondary" 
                style={{ fontSize: '0.7rem', padding: '0.2rem 0.5rem' }}
              >
                Copy Raw Log
              </button>
            </div>
            <pre className="font-mono" style={{ 
              background: '#040711', 
              padding: '1rem', 
              borderRadius: '0.5rem', 
              border: '1px solid var(--border-prominent)', 
              fontSize: '0.75rem', 
              color: '#a5b4fc', 
              overflowX: 'auto',
              maxHeight: '600px'
            }}>
              {JSON.stringify(raw_log, null, 2)}
            </pre>
          </div>
        )}

      </div>

    </div>
  );
}
