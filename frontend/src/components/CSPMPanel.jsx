import React, { useState } from 'react';
import { ShieldCheck, ShieldAlert, CheckCircle2, XCircle, Copy, Check, ExternalLink, Terminal } from 'lucide-react';

export default function CSPMPanel({ cspmData }) {
  if (!cspmData) return null;

  const [cloudFilter, setCloudFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [copiedId, setCopiedId] = useState(null);

  const handleCopy = (cmd, id) => {
    navigator.clipboard.writeText(cmd);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredFindings = cspmData.findings.filter((f) => {
    if (cloudFilter !== 'all' && f.cloud !== cloudFilter) return false;
    if (statusFilter !== 'all' && f.status.toLowerCase() !== statusFilter.toLowerCase()) return false;
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      
      {/* Posture Score Overview Banner */}
      <div className="soc-card" style={{ padding: '1.5rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
          <div style={{ 
            width: '80px', 
            height: '80px', 
            borderRadius: '50%', 
            background: cspmData.posture_score >= 80 ? 'rgba(16, 185, 129, 0.15)' : 'rgba(249, 115, 22, 0.15)',
            border: `3px solid ${cspmData.posture_score >= 80 ? '#10b981' : '#f97316'}`,
            display: 'flex', 
            flexDirection: 'column',
            alignItems: 'center', 
            justifyContent: 'center' 
          }}>
            <span style={{ fontSize: '1.4rem', fontWeight: 800, color: '#ffffff' }}>{cspmData.posture_score}%</span>
            <span style={{ fontSize: '0.65rem', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 600 }}>Score</span>
          </div>

          <div>
            <h2 style={{ fontSize: '1.2rem', fontWeight: 700, color: '#ffffff', marginBottom: '0.25rem' }}>
              Cloud Security Posture Management (CSPM)
            </h2>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Proactive CIS Benchmark and Cloud Architecture guardrail compliance checks.
            </p>
          </div>
        </div>

        {/* Passing vs Failing Counters */}
        <div style={{ display: 'flex', gap: '1.5rem' }}>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--status-success)' }}>
              {cspmData.passed_checks}
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
              Passing Controls
            </div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--sev-critical)' }}>
              {cspmData.failed_checks}
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
              Failing Controls
            </div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#ffffff' }}>
              {cspmData.total_checks}
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
              Total Evaluated
            </div>
          </div>
        </div>
      </div>

      {/* Filter Controls */}
      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
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

        <div style={{ display: 'flex', background: 'var(--bg-base)', padding: '0.2rem', borderRadius: '0.4rem', border: '1px solid var(--border-subtle)' }}>
          {['all', 'failed', 'passed'].map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              style={{
                padding: '0.3rem 0.75rem',
                fontSize: '0.75rem',
                fontWeight: 600,
                borderRadius: '0.3rem',
                border: 'none',
                cursor: 'pointer',
                background: statusFilter === s ? 'var(--bg-surface-elevated)' : 'transparent',
                color: statusFilter === s ? 'var(--text-primary)' : 'var(--text-muted)',
                textTransform: 'capitalize'
              }}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Findings List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
        {filteredFindings.map((finding) => {
          const isFailed = finding.status === 'FAILED';

          return (
            <div 
              key={finding.id} 
              className="soc-card" 
              style={{ 
                padding: '1.25rem',
                borderLeft: isFailed ? '4px solid #ef4444' : '4px solid #10b981'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  {isFailed ? <XCircle size={18} color="#ef4444" /> : <CheckCircle2 size={18} color="#10b981" />}
                  <span style={{ fontWeight: 700, fontSize: '0.95rem', color: '#ffffff' }}>
                    {finding.title}
                  </span>
                  <span className={`soc-badge ${finding.cloud === 'aws' ? 'badge-aws' : 'badge-azure'}`}>
                    {finding.cloud}
                  </span>
                </div>

                <div style={{ display: 'flex', gap: '0.4rem' }}>
                  <span className="soc-badge badge-critical" style={{ fontSize: '0.68rem' }}>
                    {finding.severity}
                  </span>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', background: 'var(--bg-surface-elevated)', padding: '0.2rem 0.5rem', borderRadius: '0.3rem' }}>
                    {finding.benchmark}
                  </span>
                </div>
              </div>

              <p style={{ fontSize: '0.82rem', color: '#cbd5e1', marginBottom: '0.6rem' }}>
                {finding.description}
              </p>

              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.85rem', display: 'flex', gap: '1.5rem' }}>
                <span>Resource: <code className="font-mono" style={{ color: 'var(--accent-cyan)' }}>{finding.resource_id}</code></span>
                <span>Type: <strong style={{ color: '#fff' }}>{finding.resource_type}</strong></span>
              </div>

              {isFailed && (
                <div style={{ background: '#040711', border: '1px solid var(--border-prominent)', borderRadius: '0.4rem', padding: '0.75rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                    <span style={{ fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--status-warning)' }}>
                      Remediation Command:
                    </span>
                    <button
                      onClick={() => handleCopy(finding.remediation_command, finding.id)}
                      style={{
                        background: 'var(--bg-surface-elevated)',
                        border: '1px solid var(--border-prominent)',
                        color: copiedId === finding.id ? 'var(--status-success)' : 'var(--text-muted)',
                        borderRadius: '0.3rem',
                        padding: '0.2rem 0.5rem',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.3rem',
                        fontSize: '0.7rem'
                      }}
                    >
                      {copiedId === finding.id ? <Check size={12} /> : <Copy size={12} />}
                      {copiedId === finding.id ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <code className="font-mono" style={{ fontSize: '0.75rem', color: '#38bdf8', wordBreak: 'break-all' }}>
                    {finding.remediation_command}
                  </code>

                  <div style={{ marginTop: '0.5rem', paddingTop: '0.5rem', borderTop: '1px solid var(--border-subtle)', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                    IaC Fix: <code className="font-mono" style={{ color: '#a5b4fc' }}>{finding.iac_recommendation}</code>
                  </div>
                </div>
              )}

            </div>
          );
        })}
      </div>

    </div>
  );
}
