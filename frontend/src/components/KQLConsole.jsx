import React, { useState } from 'react';
import { Terminal, Play, RotateCcw, Download, Sparkles } from 'lucide-react';

const QUICK_QUERIES = [
  {
    title: 'High Risk Threats',
    query: 'where risk_score >= 65 | sort by risk_score desc | take 25',
  },
  {
    title: 'Impossible Travel & Tor',
    query: 'where src_city == "Frankfurt" or category == "authentication" | sort by risk_score desc',
  },
  {
    title: 'IAM & RBAC Mutations',
    query: 'where action contains "policy" or action contains "role" | project timestamp, cloud, actor, action, risk_score',
  },
  {
    title: 'AWS VPC Flow Traffic',
    query: 'where service == "vpc_flow" | sort by bytes desc | take 15',
  },
];

export default function KQLConsole({ onRunKQL, kqlResults, isRunning }) {
  const [query, setQuery] = useState('where risk_score >= 60 | sort by risk_score desc | take 20');

  const handleExecute = () => {
    onRunKQL(query);
  };

  return (
    <div className="soc-card" style={{ padding: '1.25rem' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <div style={{ background: 'rgba(56, 189, 248, 0.1)', padding: '0.4rem', borderRadius: '0.4rem', color: 'var(--accent-cyan)' }}>
            <Terminal size={18} />
          </div>
          <div>
            <h2 style={{ fontSize: '1rem', fontWeight: 700, color: '#ffffff' }}>
              Azure Sentinel & KQL Investigation Console
            </h2>
            <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              Query multi-cloud OCSF telemetry using pipe-delimited Kusto Query Language syntax
            </p>
          </div>
        </div>

        {/* Quick Query Chips */}
        <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
          {QUICK_QUERIES.map((q, idx) => (
            <button
              key={idx}
              onClick={() => {
                setQuery(q.query);
                onRunKQL(q.query);
              }}
              style={{
                background: 'var(--bg-surface-elevated)',
                border: '1px solid var(--border-prominent)',
                borderRadius: '0.35rem',
                color: 'var(--text-secondary)',
                fontSize: '0.72rem',
                padding: '0.25rem 0.55rem',
                cursor: 'pointer',
                fontWeight: 600,
              }}
              onMouseEnter={(e) => e.currentTarget.style.borderColor = 'var(--accent-cyan)'}
              onMouseLeave={(e) => e.currentTarget.style.borderColor = 'var(--border-prominent)'}
            >
              {q.title}
            </button>
          ))}
        </div>
      </div>

      {/* Query Input Editor */}
      <div style={{ position: 'relative', marginBottom: '1rem' }}>
        <textarea
          className="font-mono"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          rows={3}
          style={{
            width: '100%',
            background: '#040711',
            border: '1px solid var(--border-prominent)',
            borderRadius: '0.5rem',
            padding: '0.85rem 1rem',
            color: '#38bdf8',
            fontSize: '0.85rem',
            outline: 'none',
            resize: 'vertical',
          }}
          placeholder='where cloud == "aws" | where risk_score > 50 | sort by risk_score desc'
        />
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem', gap: '0.5rem' }}>
          <button
            onClick={() => setQuery('')}
            className="soc-btn soc-btn-secondary"
            style={{ fontSize: '0.75rem', padding: '0.4rem 0.75rem' }}
          >
            <RotateCcw size={13} /> Clear
          </button>
          <button
            onClick={handleExecute}
            disabled={isRunning}
            className="soc-btn soc-btn-primary"
            style={{ fontSize: '0.75rem', padding: '0.4rem 1rem' }}
          >
            <Play size={13} /> {isRunning ? 'Executing...' : 'Run Query'}
          </button>
        </div>
      </div>

      {/* Results Section */}
      {kqlResults && (
        <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Returned <strong style={{ color: '#ffffff' }}>{kqlResults.count}</strong> records matching pipeline.
            </span>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
              Execution time: &lt;5ms (In-Memory KQL Engine)
            </span>
          </div>

          <div style={{ overflowX: 'auto', maxHeight: '420px', borderRadius: '0.4rem', border: '1px solid var(--border-subtle)' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.78rem' }}>
              <thead style={{ position: 'sticky', top: 0, background: 'var(--bg-surface-elevated)' }}>
                <tr style={{ borderBottom: '1px solid var(--border-prominent)' }}>
                  {kqlResults.columns && kqlResults.columns.map((col, idx) => (
                    <th key={idx} style={{ padding: '0.6rem 0.85rem', textTransform: 'uppercase', color: 'var(--text-muted)', fontSize: '0.68rem', letterSpacing: '0.04em' }}>
                      {col}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {kqlResults.rows && kqlResults.rows.length === 0 ? (
                  <tr>
                    <td colSpan={kqlResults.columns?.length || 1} style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                      Query returned 0 results.
                    </td>
                  </tr>
                ) : (
                  kqlResults.rows.map((row, rIdx) => (
                    <tr 
                      key={rIdx} 
                      style={{ borderBottom: '1px solid var(--border-subtle)' }}
                      onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-surface-hover)'}
                      onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                    >
                      {kqlResults.columns.map((col, cIdx) => (
                        <td key={cIdx} className="font-mono" style={{ padding: '0.55rem 0.85rem', whiteSpace: 'nowrap' }}>
                          {col === 'risk_score' ? (
                            <span style={{ 
                              fontWeight: 700, 
                              color: row[col] >= 65 ? '#f87171' : '#38bdf8' 
                            }}>
                              {row[col]}
                            </span>
                          ) : (
                            String(row[col] !== undefined ? row[col] : '')
                          )}
                        </td>
                      ))}
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

    </div>
  );
}
