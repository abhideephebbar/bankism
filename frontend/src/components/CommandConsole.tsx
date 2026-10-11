import React from 'react';
import { DEMO_SCENARIOS, DemoScenario } from '../config/demoScenarios';
import { Decision } from '../types/firewall';

interface CommandConsoleProps {
  message: string;
  memo: string;
  onMessageChange: (val: string) => void;
  onMemoChange: (val: string) => void;
  onEvaluate: () => void;
  onOpenProcessModal: () => void;
  onOpenExecutionBoundaryModal: () => void;
  isEvaluating: boolean;
  isProcessing: boolean;
  latestDecision: Decision | null;
  isVerdictStale: boolean;
}

export const CommandConsole: React.FC<CommandConsoleProps> = ({
  message,
  memo,
  onMessageChange,
  onMemoChange,
  onEvaluate,
  onOpenProcessModal,
  onOpenExecutionBoundaryModal,
  isEvaluating,
  isProcessing,
  latestDecision,
  isVerdictStale,
}) => {
  const isAnyInFlight = isEvaluating || isProcessing;
  const isMessageValid = message.trim().length >= 1 && message.length <= 500;
  const isMemoValid = memo.length <= 140;

  // Normal Process is offered only for a fresh, unedited APPROVE verdict.
  const canNormalProcess =
    latestDecision === 'APPROVE' && !isVerdictStale && !isAnyInFlight;

  // Demonstrates server-side enforcement; only for a fresh, unedited BLOCK verdict.
  const canAttemptProcessAnyway =
    latestDecision === 'BLOCK' && !isVerdictStale && !isAnyInFlight;

  const handleSelectScenario = (scenario: DemoScenario) => {
    onMessageChange(scenario.message);
    onMemoChange(scenario.memo || '');
  };

  return (
    <section
      className="bankism-panel"
      aria-label="Banking request"
      style={{ animation: 'fadeUp 480ms cubic-bezier(0.22, 1, 0.36, 1) both' }}
    >
      {/* Natural-language request — the primary input */}
      <div className="input-group">
        <div className="input-label">
          <label htmlFor="banking-message-input">Natural-language request</label>
          <span
            className={`input-char-counter ${message.length > 450 ? 'limit-near' : ''}`}
          >
            {message.length} / 500
          </span>
        </div>
        <textarea
          id="banking-message-input"
          className="bankism-textarea"
          value={message}
          onChange={(e) => onMessageChange(e.target.value)}
          placeholder="e.g. 'send 500 to Priya' or 'check my balance'"
          maxLength={500}
          disabled={isAnyInFlight}
          rows={3}
          aria-required="true"
        />
      </div>

      {/* Optional memo — visually secondary */}
      <div className="input-group" style={{ opacity: 0.85 }}>
        <div className="input-label">
          <label htmlFor="banking-memo-input">Memo (optional)</label>
          <span
            className={`input-char-counter ${memo.length > 120 ? 'limit-near' : ''}`}
          >
            {memo.length} / 140
          </span>
        </div>
        <input
          id="banking-memo-input"
          type="text"
          className="bankism-input"
          value={memo}
          onChange={(e) => onMemoChange(e.target.value)}
          placeholder="e.g. 'rent for October'"
          maxLength={140}
          disabled={isAnyInFlight}
        />
      </div>

      {/* Actions */}
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: 12,
          marginTop: 18,
          alignItems: 'center',
        }}
      >
        <button
          type="button"
          className="btn btn-primary"
          onClick={onEvaluate}
          disabled={!isMessageValid || !isMemoValid || isAnyInFlight}
          aria-label="Evaluate request via firewall"
        >
          {isEvaluating ? 'Evaluating…' : 'Evaluate'}
        </button>

        <button
          type="button"
          className="btn btn-execute"
          onClick={onOpenProcessModal}
          disabled={!canNormalProcess}
          title={
            !latestDecision
              ? 'Evaluate the request first'
              : latestDecision === 'BLOCK'
              ? 'Blocked requests cannot be processed'
              : isVerdictStale
              ? 'Inputs changed since evaluation — evaluate again'
              : 'Execute the simulated transaction'
          }
          aria-label="Process transaction"
        >
          {isProcessing ? 'Processing…' : 'Process'}
        </button>

        {latestDecision === 'BLOCK' && (
          <button
            type="button"
            className="btn btn-danger font-mono"
            onClick={onOpenExecutionBoundaryModal}
            disabled={!canAttemptProcessAnyway}
            title={
              isVerdictStale
                ? 'Verdict is stale; re-evaluate before testing the execution boundary'
                : 'Submit to the server to demonstrate enforcement'
            }
            style={{ fontSize: 11 }}
          >
            ATTEMPT PROCESS ANYWAY (SERVER WILL ENFORCE)
          </button>
        )}
      </div>

      {isVerdictStale && latestDecision && (
        <div
          className="font-mono"
          style={{
            marginTop: 14,
            padding: '8px 12px',
            background: 'rgba(255, 170, 0, 0.09)',
            border: '1px solid rgba(255, 170, 0, 0.3)',
            color: 'var(--color-amber)',
            fontSize: 11,
            borderRadius: 8,
          }}
          role="status"
        >
          INPUTS MODIFIED: Displayed verdict is STALE. Re-evaluate to obtain a fresh security decision.
        </div>
      )}

      {/* Demo scenarios */}
      <div style={{ marginTop: 20 }}>
        <div className="input-label" style={{ marginBottom: 4 }}>
          <span>Try an example</span>
          <span className="text-muted" style={{ fontSize: 11 }}>
            fills the inputs only
          </span>
        </div>
        <div className="scenario-chips-container">
          {DEMO_SCENARIOS.map((sc) => (
            <button
              key={sc.id}
              type="button"
              className={`scenario-chip ${sc.category === 'adversarial' ? 'adversarial' : ''}`}
              onClick={() => handleSelectScenario(sc)}
              disabled={isAnyInFlight}
              title={sc.description}
            >
              <span>{sc.label}</span>
            </button>
          ))}
        </div>
      </div>

      <p
        className="console-supporting-line"
      >
        Check your balance or describe a simulated transfer. Bankism evaluates each
        request before any action can proceed.
      </p>
    </section>
  );
};
