import React, { useState } from 'react';
import { EvaluationUiStatus, RequestSnapshot, Verdict } from '../types/firewall';
import { getBlockHeadlineInfo, getThreatCategoryLabel } from '../utils/validation';
import { RawJsonSection } from './RawJsonSection';

interface VerdictPanelProps {
  verdict: Verdict | null;
  uiStatus: EvaluationUiStatus;
  errorMessage: string | null;
  isStale: boolean;
  onRetry?: () => void;
  rawResponseJson?: unknown;
  snapshot?: RequestSnapshot | null;
}

const RISK_BADGE: Record<string, string> = {
  LOW: 'badge-low',
  MEDIUM: 'badge-medium',
  HIGH: 'badge-high',
  CRITICAL: 'badge-critical',
};

export const VerdictPanel: React.FC<VerdictPanelProps> = ({
  verdict,
  uiStatus,
  errorMessage,
  isStale,
  onRetry,
  rawResponseJson,
  snapshot,
}) => {
  const [showDetails, setShowDetails] = useState(false);

  // 1. Idle
  if (uiStatus === 'IDLE' && !verdict) {
    return (
      <div
        className="bankism-panel"
        style={{ minHeight: 180, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}
        aria-live="polite"
      >
        <p className="text-secondary" style={{ fontSize: 14 }}>
          The security result will appear here after you evaluate a request.
        </p>
      </div>
    );
  }

  // 2. HTTP 422 / schema rejection — a format error, never a security verdict.
  if (uiStatus === 'REQUEST_REJECTED') {
    return (
      <div
        className="bankism-panel"
        style={{ borderColor: 'rgba(255, 170, 0, 0.35)' }}
        aria-live="polite"
      >
        <div className="panel-header">
          <span className="panel-title text-amber">REQUEST REJECTED</span>
          <span className="badge badge-medium">HTTP 422 CLIENT ERROR</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <p className="text-secondary" style={{ fontSize: 13 }}>
            The request format was rejected before security evaluation.
          </p>

          {errorMessage && (
            <div
              className="font-mono"
              style={{
                fontSize: 12,
                color: 'var(--color-amber)',
                background: 'rgba(255, 170, 0, 0.08)',
                padding: '10px 12px',
                borderRadius: 6,
                borderLeft: '2px solid var(--color-amber)',
                wordBreak: 'break-word',
              }}
            >
              {errorMessage}
            </div>
          )}

          <div className="font-mono text-muted" style={{ fontSize: 11 }}>
            This is a request format error, not a security block.
          </div>
        </div>
      </div>
    );
  }

  // 3. System error / unavailable verdict — nothing is fabricated.
  if (uiStatus === 'SYSTEM_ERROR') {
    return (
      <div
        className="bankism-panel"
        style={{ borderColor: 'rgba(255, 42, 95, 0.3)' }}
        aria-live="polite"
      >
        <div className="panel-header">
          <span className="panel-title text-red">SYSTEM ERROR // VERDICT UNAVAILABLE</span>
          <span className="badge badge-high">COMMUNICATION FAILURE</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div className="text-red result-headline" style={{ fontSize: 16 }}>
            SYSTEM ERROR — VERDICT UNAVAILABLE
          </div>

          <p className="text-secondary" style={{ fontSize: 13 }}>
            A network problem or an invalid response prevented a verified security verdict. No verdict was fabricated.
          </p>

          {errorMessage && (
            <div
              className="font-mono text-red"
              style={{
                fontSize: 12,
                background: 'rgba(255, 42, 95, 0.07)',
                padding: '10px 12px',
                borderRadius: 6,
                borderLeft: '2px solid var(--color-red)',
              }}
            >
              {errorMessage}
            </div>
          )}

          {onRetry && (
            <div>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={onRetry}
                style={{ fontSize: 12 }}
              >
                Retry evaluation
              </button>
            </div>
          )}
        </div>
      </div>
    );
  }

  // 4. Valid verdict
  if (!verdict) return null;

  const isApproved = verdict.decision === 'APPROVE';
  const headlineInfo = getBlockHeadlineInfo(verdict.threat_category, 'evaluate');

  return (
    <div
      className={`bankism-panel ${isApproved ? 'approved' : 'blocked'} ${
        isStale ? 'stale' : ''
      } result-enter`}
      aria-live="polite"
    >
      <div className="panel-header">
        <span
          className="panel-title"
          style={{ color: isApproved ? 'var(--color-green)' : 'var(--color-red)' }}
        >
          Security result
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {isStale && <span className="badge badge-stale">STALE VERDICT</span>}
          <span className={`badge ${RISK_BADGE[verdict.risk_level] || 'badge-medium'}`}>
            Risk: {verdict.risk_level}
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        {/* Headline */}
        {isApproved ? (
          <div className="headline-reveal">
            <div className="result-headline text-green">✓ REQUEST APPROVED</div>
            <div className="result-subheadline text-secondary">
              Evaluation only — no transaction has been executed.
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

        {/* Readable category */}
        <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
          {isApproved ? (
            <span>Threat: {getThreatCategoryLabel(verdict.threat_category)}</span>
          ) : (
            <span>
              {headlineInfo.isAttack ? 'Threat' : 'Reason'}:{' '}
              <span style={{ color: 'var(--text-primary)' }}>
                {getThreatCategoryLabel(verdict.threat_category)}
              </span>
            </span>
          )}
        </div>

        {/* Backend rationale */}
        <div>
          <span className="input-label" style={{ marginBottom: 4 }}>
            Explanation
          </span>
          <div
            className="result-rationale"
            style={{
              borderLeftColor: isApproved
                ? 'var(--color-green)'
                : headlineInfo.isAttack
                ? 'var(--color-red)'
                : 'var(--color-amber)',
            }}
          >
            {verdict.rationale}
          </div>
        </div>

        {/* One compact, expandable details section */}
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
                <div className="details-heading">Request</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12 }}>
                  <div>
                    <span className="text-muted">User: </span>
                    <span className="font-mono text-cyan">{snapshot?.userId || '—'}</span>
                  </div>
                  <div>
                    <span className="text-muted">Message: </span>
                    <span className="font-mono">{snapshot?.message || '—'}</span>
                  </div>
                  {snapshot?.memo && (
                    <div>
                      <span className="text-muted">Memo: </span>
                      <span className="font-mono text-secondary">{snapshot.memo}</span>
                    </div>
                  )}
                  {snapshot?.timestamp && (
                    <div className="font-mono text-muted" style={{ fontSize: 10 }}>
                      Evaluated at {new Date(snapshot.timestamp).toLocaleTimeString()}
                    </div>
                  )}
                </div>
              </div>

              <div className="details-section">
                <div className="details-heading">Parsed result</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12 }}>
                  <div>
                    <span className="text-muted">Intent: </span>
                    <span className="font-mono text-cyan">{verdict.intent}</span>
                  </div>
                  <div>
                    <span className="text-muted">Threat category: </span>
                    <span className="font-mono">{verdict.threat_category}</span>
                  </div>
                  <div>
                    <span className="text-muted">Request ID: </span>
                    <span className="font-mono text-muted">{verdict.request_id}</span>
                  </div>
                  {verdict.transaction_details && (
                    <div className="font-mono" style={{ color: 'var(--text-secondary)' }}>
                      {verdict.transaction_details.recipient && (
                        <span>
                          {verdict.transaction_details.recipient} ·{' '}
                          {verdict.transaction_details.amount}{' '}
                          {verdict.transaction_details.currency}
                          {verdict.transaction_details.memo
                            ? ` · "${verdict.transaction_details.memo}"`
                            : ''}
                        </span>
                      )}
                    </div>
                  )}
                </div>
              </div>

              {verdict.signals.length > 0 && (
                <div className="details-section">
                  <div className="details-heading">Detected signals ({verdict.signals.length})</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {verdict.signals.map((sig, idx) => (
                      <span key={idx} className="signal-chip">
                        {sig}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {verdict.validation_errors.length > 0 && (
                <div className="details-section">
                  <div className="details-heading">
                    Validation errors ({verdict.validation_errors.length})
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {verdict.validation_errors.map((err, idx) => (
                      <div key={idx} className="validation-error-item">
                        {err}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="details-section">
                <div className="details-heading">Response fields</div>
                <p className="text-muted" style={{ fontSize: 11 }}>
                  The complete response, including fields not shown above, is
                  available in Raw JSON below.
                </p>
              </div>
            </div>
          )}

          <RawJsonSection
            data={rawResponseJson || verdict}
            label="evaluation response"
          />
        </div>
      </div>
    </div>
  );
};
