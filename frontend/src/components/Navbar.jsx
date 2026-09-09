import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Cpu, 
  Sparkles, 
  Zap, 
  RefreshCw, 
  Cloud, 
  Terminal, 
  Layers, 
  AlertTriangle 
} from 'lucide-react';

export default function Navbar({ 
  stats, 
  activeTab, 
  setActiveTab, 
  onSimulate, 
  onRefresh, 
  isSimulating 
}) {
  const [showSimMenu, setShowSimMenu] = useState(false);

  const handleSimulate = (scenario) => {
    setShowSimMenu(false);
    onSimulate(scenario);
  };

  return (
    <header style={{ 
      borderBottom: '1px solid var(--border-subtle)', 
      background: 'rgba(15, 23, 42, 0.85)', 
      backdropFilter: 'blur(12px)', 
      position: 'sticky', 
      top: 0, 
      zIndex: 50 
    }}>
      <div className="soc-container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.85rem 2rem' }}>
        
        {/* Logo & Brand */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ 
            background: 'linear-gradient(135deg, #0284c7, #4f46e5)', 
            padding: '0.6rem', 
            borderRadius: '0.6rem', 
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'center',
            boxShadow: '0 0 20px rgba(2, 132, 199, 0.4)'
          }}>
            <ShieldAlert size={26} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <span style={{ fontSize: '1.25rem', fontWeight: 800, letterSpacing: '-0.02em', color: '#ffffff' }}>
                CloudSentry <span style={{ color: 'var(--accent-cyan)' }}>AI</span>
              </span>
              <span className="soc-badge" style={{ background: 'rgba(56, 189, 248, 0.1)', color: 'var(--accent-cyan)', border: '1px solid rgba(56, 189, 248, 0.3)' }}>
                v1.0 SOC
              </span>
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Multi-Cloud Autonomous Threat Detection & LLM Triage
            </p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav style={{ display: 'flex', gap: '0.4rem', background: 'var(--bg-base)', padding: '0.3rem', borderRadius: '0.5rem', border: '1px solid var(--border-subtle)' }}>
          <button 
            onClick={() => setActiveTab('alerts')} 
            className="soc-btn"
            style={{ 
              background: activeTab === 'alerts' ? 'var(--bg-surface-elevated)' : 'transparent',
              color: activeTab === 'alerts' ? 'var(--text-primary)' : 'var(--text-muted)',
              border: activeTab === 'alerts' ? '1px solid var(--border-prominent)' : '1px solid transparent',
              fontSize: '0.8rem',
              padding: '0.4rem 0.85rem'
            }}
          >
            <AlertTriangle size={15} color={activeTab === 'alerts' ? 'var(--accent-cyan)' : 'currentColor'} />
            Alert Queue
          </button>
          <button 
            onClick={() => setActiveTab('kql')} 
            className="soc-btn"
            style={{ 
              background: activeTab === 'kql' ? 'var(--bg-surface-elevated)' : 'transparent',
              color: activeTab === 'kql' ? 'var(--text-primary)' : 'var(--text-muted)',
              border: activeTab === 'kql' ? '1px solid var(--border-prominent)' : '1px solid transparent',
              fontSize: '0.8rem',
              padding: '0.4rem 0.85rem'
            }}
          >
            <Terminal size={15} color={activeTab === 'kql' ? 'var(--accent-cyan)' : 'currentColor'} />
            KQL Console
          </button>
          <button 
            onClick={() => setActiveTab('cspm')} 
            className="soc-btn"
            style={{ 
              background: activeTab === 'cspm' ? 'var(--bg-surface-elevated)' : 'transparent',
              color: activeTab === 'cspm' ? 'var(--text-primary)' : 'var(--text-muted)',
              border: activeTab === 'cspm' ? '1px solid var(--border-prominent)' : '1px solid transparent',
              fontSize: '0.8rem',
              padding: '0.4rem 0.85rem'
            }}
          >
            <Cloud size={15} color={activeTab === 'cspm' ? 'var(--accent-cyan)' : 'currentColor'} />
            CSPM Posture
          </button>
        </nav>

        {/* Engine Status & Simulation Actions */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
          
          {/* Health Indicators */}
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <span style={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: '0.35rem', 
              fontSize: '0.72rem', 
              padding: '0.25rem 0.6rem', 
              borderRadius: '9999px',
              background: 'rgba(16, 185, 129, 0.1)', 
              color: 'var(--status-success)', 
              border: '1px solid rgba(16, 185, 129, 0.25)' 
            }}>
              <Cpu size={12} /> PyTorch Engine
            </span>
            <span style={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: '0.35rem', 
              fontSize: '0.72rem', 
              padding: '0.25rem 0.6rem', 
              borderRadius: '9999px',
              background: 'rgba(99, 102, 241, 0.1)', 
              color: 'var(--accent-indigo)', 
              border: '1px solid rgba(99, 102, 241, 0.25)' 
            }}>
              <Sparkles size={12} /> LLM Triage
            </span>
          </div>

          {/* Refresh Button */}
          <button 
            onClick={onRefresh}
            className="soc-btn soc-btn-secondary" 
            style={{ padding: '0.45rem', borderRadius: '0.45rem' }} 
            title="Refresh Alert Stream"
          >
            <RefreshCw size={15} />
          </button>

          {/* Attack Simulator Dropdown */}
          <div style={{ position: 'relative' }}>
            <button 
              onClick={() => setShowSimMenu(!showSimMenu)}
              className="soc-btn soc-btn-primary"
              disabled={isSimulating}
              style={{ fontSize: '0.8rem', padding: '0.45rem 0.85rem' }}
            >
              <Zap size={14} className={isSimulating ? 'animate-spin' : ''} />
              {isSimulating ? 'Injecting Attack...' : 'Simulate Threat'}
            </button>

            {showSimMenu && (
              <div style={{ 
                position: 'absolute', 
                right: 0, 
                marginTop: '0.5rem', 
                background: 'var(--bg-surface-elevated)', 
                border: '1px solid var(--border-prominent)', 
                borderRadius: '0.5rem', 
                width: '280px', 
                boxShadow: '0 10px 30px rgba(0, 0, 0, 0.6)', 
                padding: '0.4rem', 
                zIndex: 100 
              }}>
                <div style={{ padding: '0.4rem 0.6rem', fontSize: '0.7rem', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 700 }}>
                  Inject Adversary Scenario
                </div>
                <button 
                  onClick={() => handleSimulate('impossible_travel')}
                  style={{ width: '100%', textAlign: 'left', padding: '0.5rem 0.6rem', background: 'transparent', border: 'none', color: 'var(--text-primary)', borderRadius: '0.35rem', cursor: 'pointer', fontSize: '0.8rem', display: 'flex', flexDirection: 'column' }}
                  onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-surface-hover)'}
                  onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                >
                  <span style={{ fontWeight: 600, color: '#f87171' }}>• Impossible Travel (Azure Entra ID)</span>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Tor exit node login from Frankfurt (T1078)</span>
                </button>
                <button 
                  onClick={() => handleSimulate('iam_escalation')}
                  style={{ width: '100%', textAlign: 'left', padding: '0.5rem 0.6rem', background: 'transparent', border: 'none', color: 'var(--text-primary)', borderRadius: '0.35rem', cursor: 'pointer', fontSize: '0.8rem', display: 'flex', flexDirection: 'column' }}
                  onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-surface-hover)'}
                  onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                >
                  <span style={{ fontWeight: 600, color: '#f87171' }}>• IAM Privilege Escalation (AWS)</span>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>AdministratorAccess backdoor attachment (T1098)</span>
                </button>
                <button 
                  onClick={() => handleSimulate('s3_exfiltration')}
                  style={{ width: '100%', textAlign: 'left', padding: '0.5rem 0.6rem', background: 'transparent', border: 'none', color: 'var(--text-primary)', borderRadius: '0.35rem', cursor: 'pointer', fontSize: '0.8rem', display: 'flex', flexDirection: 'column' }}
                  onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-surface-hover)'}
                  onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                >
                  <span style={{ fontWeight: 600, color: '#fb923c' }}>• S3 Data Exfiltration & Ransomware</span>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Bulk GetObject & policy lockout (T1530)</span>
                </button>
                <button 
                  onClick={() => handleSimulate('c2_beaconing')}
                  style={{ width: '100%', textAlign: 'left', padding: '0.5rem 0.6rem', background: 'transparent', border: 'none', color: 'var(--text-primary)', borderRadius: '0.35rem', cursor: 'pointer', fontSize: '0.8rem', display: 'flex', flexDirection: 'column' }}
                  onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-surface-hover)'}
                  onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                >
                  <span style={{ fontWeight: 600, color: '#fb923c' }}>• VPC Flow C2 Beaconing (AWS)</span>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>TCP port 4444 periodic pulse (T1071)</span>
                </button>
                <button 
                  onClick={() => handleSimulate('azure_rbac')}
                  style={{ width: '100%', textAlign: 'left', padding: '0.5rem 0.6rem', background: 'transparent', border: 'none', color: 'var(--text-primary)', borderRadius: '0.35rem', cursor: 'pointer', fontSize: '0.8rem', display: 'flex', flexDirection: 'column' }}
                  onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-surface-hover)'}
                  onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                >
                  <span style={{ fontWeight: 600, color: '#f87171' }}>• Rogue Subscription Owner (Azure)</span>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>RBAC backdoor to external guest (T1098.003)</span>
                </button>
              </div>
            )}
          </div>

        </div>

      </div>
    </header>
  );
}
