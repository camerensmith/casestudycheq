import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }
  static getDerivedStateFromError(error) {
    return { error }
  }
  render() {
    if (this.state.error) {
      return (
        <div style={{ fontFamily: 'system-ui, sans-serif', background: '#070b16', minHeight: '100vh', color: '#e2e8f0', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
          <div style={{ textAlign: 'center', maxWidth: 480 }}>
            <div style={{ fontSize: 36, marginBottom: 16 }}>⚠️</div>
            <h2 style={{ fontSize: 20, fontWeight: 700, marginBottom: 12, color: '#f1f5f9' }}>Something went wrong</h2>
            <p style={{ color: '#64748b', fontSize: 14, lineHeight: 1.6, marginBottom: 20 }}>
              The application encountered an unexpected error. Try refreshing the page.
            </p>
            <pre style={{ background: '#0c1225', borderRadius: 8, padding: '12px 16px', fontSize: 11, color: '#94a3b8', textAlign: 'left', overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
              {String(this.state.error)}
            </pre>
            <button
              onClick={() => window.location.reload()}
              style={{ marginTop: 20, padding: '10px 28px', borderRadius: 10, border: 'none', cursor: 'pointer', fontSize: 13, fontWeight: 600, color: '#fff', background: 'linear-gradient(135deg,#f43f5e,#e11d48)' }}
            >
              Reload
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>,
)
