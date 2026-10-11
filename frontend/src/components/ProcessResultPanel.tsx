import React, { useState } from 'react';
import { ProcessResponse, ProcessUiStatus } from '../types/firewall';
import { getBlockHeadlineInfo } from '../utils/validation';
import { RawJsonSection } from './RawJsonSection';

interface ProcessResultPanelProps {
  processResult: ProcessResponse | null;
  uiStatus: ProcessUiStatus;
  errorMessage: string | null;
  onClear?: () => void;
}

export const ProcessResultPanel: React.FC<ProcessResultPanelProps> = ({
  processResult,
  uiStatus,
  errorMessage,
  onClear,
}) => {
  const [showDetails, setShowDetails] = useState(false);

  if (uiStatus === 'IDLE' && !processResult) {
    return null;
  }

  // Uncertain outcome: timeout, network loss, or malformed response after submission.
  if (uiStatus === 'EXECUTION_UNKNOWN') {
    return (
      <div
        className="bankism-panel result-enter"
        style={{ borderColor: 'rgba(255, 170, 0, 0.4)' }}
        role="alert"
        aria-live="assertive"
      >
        <div className="panel-header">
          <span className="panel-title text-amber">PROCESS RESULT</span>
          <span className="badge badge-medium">UNRESOLVED OUTCOME</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div className="result-headline text-amber">EXECUTION STATUS UNKNOWN</div>

          <p className="text-secondary" style={{ fontSize: 13, lineHeight: 1.6 }}>
            The connection dropped while waiting for the process response.
            <br />
            <strong style={{ color: 'var(--text-primary)' }}>Important:</strong> The
            backend may have completed the simulated transfer even though the response
            was not received. This operation has NOT been marked as blocked or failed,
            and has NOT been automatically retried.
          </p>

          <div
            className="font-mono text-amber"
            style={{
              fontSize: 12,
              background: 'rgba(255, 170, 0, 0.07)',
              padding: '10px 12px',
              borderRadius: 6,
              borderLeft: '2px solid var(--color-amber)',
            }}
          >
            {errorMessage || 'Connection lost before the response arrived.'}
          </div>

          <p className="text-muted" style={{ fontSize: 12 }}>
            Check the balance or service state before attempting another transfer.
          </p>

          {onClear && (
            <div>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={onClear}
                style={{ fontSize: 12 }}
              >
                Dismiss
              </button>
            </div>
          )}
        </div>
      </div>
    );
  }

  // HTTP 422 rejection on the process endpoint.
  if (uiStatus === 'REQUEST_REJECTED') {
    return (
      <div
        className="bankism-panel result-enter"
        style={{ borderColor: 'rgba(255, 170, 0, 0.35)' }}
        role="alert"
        aria-live="polite"
      >
        <div className="panel-header">
          <span className="panel-title text-amber">PROCESS REQUEST REJECTED</span>
          <span className="badge badge-medium">HTTP 422</span>
        </div>

        <p className="text-secondary" style={{ fontSize: 13 }}>
          {errorMessage || 'The process request format was rejected.'}
        </p>

        {onClear && (
          <div style={{ marginTop: 12 }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={onClear}
              style={{ fontSize: 12 }}
            >
              Dismiss
            </button>
          </div>
        )}
      </div>
    );
  }

  if (!processResult) return null;

  const { verdict, action_executed, simulated, transaction_id, balance } = processResult;
  const isApprovedAndExecuted = action_executed && verdict.decision === 'APPROVE';
  const headlineInfo = getBlockHeadlineInfo(verdict.threat_category, 'process', {
    action_executed,
    simulated,
  });

  return (
    <div
      className={`bankism-panel result-enter ${isApprovedAndExecuted ? 'approved' : 'blocked'}`}
      role="region"
      aria-label="Process execution result"
      aria-live="polite"
    >
      <div className="panel-header">
        <span
          className="panel-title"
          style={{
            color: isApprovedAndExecuted ? 'var(--color-green)' : 'var(--color-red)',
          }}
        >
          {isApprovedAndExecuted ? 'Transaction result' : 'Server enforcement'}
        </span>
        <div style={{ display: 'flex', gap: 6 }}>
          {simulated && <span className="badge badge-simulated">Simulated</span>}
          <span className={`badge ${isApprovedAndExecuted ? 'badge-low' : 'badge-high'}`}>
            {action_executed ? 'Executed' : 'Refused'}
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {isApprovedAndExecuted ? (
          <div className="headline-reveal">
            <div className="result-headline text-green">✓ ACTION EXECUTED (SIMULATED)</div>
            <div className="result-subheadline text-secondary">
              The server approved and completed the transaction in memory.
            </div>
          </div>
        ) : (
          <div className="headline-reveal">
            <div className={`result-headline ${headlineInfo.isAttack ? 'text-red' : 'text-amber'}`}>
              {headlineInfo.headline}
            </div>
            <div
              className="result-subheadline font-mono"
              style={{ color: headlineInfo.isAttack ? 'var(--color-red)' : 'var(--text-secondary)' }}
            >
              {headlineInfo.subheadline}
            </div>
          </div>
        )}

        {isApprovedAndExecuted ? (
          <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
            {transaction_id && (
              <div>
                <span className="text-muted">Transaction: </span>
                <span className="font-mono text-cyan">{transaction_id}</span>
              </div>
            )}
            {balance && (
              <div>
                <span className="text-muted">New balance: </span>
                <span className="font-mono text-green">{balance} INR</span>
              </div>
            )}
          </div>
        ) : (
          <div>
            <span className="input-label" style={{ marginBottom: 4 }}>
              Explanation
            </span>
            <div
              className="result-rationale"
              style={{ borderLeftColor: 'var(--color-red)', fontSize: 13 }}
            >
              {verdict.rationale}
            </div>
          </div>
        )}

        {/* Details disclosure */}
        <div style={{ marginTop: 2 }}>
          <button
            type="button"
            className="details-toggle"
            onClick={() => setShowDetails(!showDetails)}
            aria-expanded={showDetails}
          >
            <span className="chevron" aria-hidden="true">
              ▶
            </span>
            {showDetails ? 'Hide details' : 'View details'}
          </button>

          {showDetails && (
            <div className="details-body">
              <div className="details-section">
                <div className="details-heading">Execution</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12 }}>
                  <div>
                    <span className="text-muted">Action executed: </span>
                    <span
                      className="font-mono"
                      style={{
                        fontWeight: 700,
                        color: action_executed ? 'var(--color-green)' : 'var(--color-red)',
                      }}
                    >
                      {String(action_executed)}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted">Simulated environment: </span>
                    <span className="font-mono text-cyan">{String(simulated)}</span>
                  </div>
                  <div>
                    <span className="text-muted">Decision: </span>
                    <span className="font-mono">{verdict.decision}</span>
                  </div>
                  <div>
                    <span className="text-muted">Threat category: </span>
                    <span className="font-mono">{verdict.threat_category}</span>
                  </div>
                  <div>
                    <span className="text-muted">Risk level: </span>
                    <span className="font-mono">{verdict.risk_level}</span>
                  </div>
                </div>
              </div>

              <div className="details-section">
                <div className="details-heading">Response fields</div>
                <p className="text-muted" style={{ fontSize: 11 }}>
                  The complete process response, including fields not shown above,
                  is available in Raw JSON below.
                </p>
              </div>
            </div>
          )}

          <RawJsonSection
            data={processResult}
            label="process response"
          />
        </div>

        {onClear && (
          <div style={{ marginTop: 2 }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={onClear}
              style={{ fontSize: 12 }}
            >
              Clear result
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
