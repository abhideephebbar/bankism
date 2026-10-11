import React, { useEffect, useRef } from 'react';
import { Verdict } from '../types/firewall';

interface ProcessModalProps {
  isOpen: boolean;
  mode: 'normal' | 'execution_boundary';
  verdict: Verdict | null;
  userId: string;
  onConfirm: () => void;
  onCancel: () => void;
  isProcessing: boolean;
}

export const ProcessModal: React.FC<ProcessModalProps> = ({
  isOpen,
  mode,
  verdict,
  userId,
  onConfirm,
  onCancel,
  isProcessing,
}) => {
  const modalRef = useRef<HTMLDivElement>(null);
  const confirmBtnRef = useRef<HTMLButtonElement>(null);

  // Focus trap & Escape handler
  useEffect(() => {
    if (!isOpen) return;

    confirmBtnRef.current?.focus();

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !isProcessing) {
        onCancel();
        return;
      }

      if (e.key === 'Tab' && modalRef.current) {
        const focusable = modalRef.current.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        if (focusable.length === 0) return;

        const firstElement = focusable[0];
        const lastElement = focusable[focusable.length - 1];

        if (e.shiftKey && document.activeElement === firstElement) {
          e.preventDefault();
          lastElement.focus();
        } else if (!e.shiftKey && document.activeElement === lastElement) {
          e.preventDefault();
          firstElement.focus();
        }
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onCancel, isProcessing]);

  if (!isOpen) return null;

  const isExecutionBoundary = mode === 'execution_boundary';
  const txnDetails = verdict?.transaction_details;
  const isTransfer = verdict?.intent === 'TRANSFER';
  const isBalanceInquiry = verdict?.intent === 'BALANCE_INQUIRY';

  return (
    <div
      className="modal-backdrop"
      onClick={() => {
        if (!isProcessing) onCancel();
      }}
      role="presentation"
    >
      <div
        ref={modalRef}
        className={`modal-dialog ${isExecutionBoundary ? 'danger' : ''}`}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="process-modal-title"
        aria-describedby="process-modal-description"
      >
        <div className="panel-header">
          <span
            id="process-modal-title"
            className={`panel-title ${isExecutionBoundary ? 'text-red' : 'text-cyan'}`}
          >
            {isExecutionBoundary
              ? 'CONFIRM EXECUTION BOUNDARY DEMO'
              : 'CONFIRM SIMULATED TRANSACTION EXECUTION'}
          </span>
          <span className="badge badge-simulated">100% SIMULATED</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {isExecutionBoundary ? (
            <div
              className="font-mono text-red"
              style={{
                background: 'rgba(255, 42, 95, 0.1)',
                border: '1px solid var(--color-red)',
                padding: '12px',
                borderRadius: 2,
                fontSize: 13,
                lineHeight: 1.5,
              }}
              id="process-modal-description"
            >
              The last evaluation was BLOCK. This demonstrates that the server refuses it independently. Nothing is expected to execute.
            </div>
          ) : (
            <div
              className="font-mono text-secondary"
              style={{ fontSize: 13, lineHeight: 1.5 }}
              id="process-modal-description"
            >
              You are about to submit this request for simulated execution via{' '}
              <code className="text-cyan">/api/v1/process</code>.
              <br />
              <strong style={{ color: 'var(--text-primary)' }}>
                Security Notice:
              </strong>{' '}
              The server will independently re-evaluate the request against all security rules before executing. Evaluation approval does not guarantee execution safety.
            </div>
          )}

          {/* Operation preview */}
          <div
            style={{
              background: 'rgba(0, 0, 0, 0.35)',
              border: '1px solid rgba(0, 242, 254, 0.2)',
              padding: '12px 14px',
              borderRadius: 8,
            }}
          >
            <span className="input-label" style={{ marginBottom: 6 }}>
              Details
            </span>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 13 }}>
              <div>
                <span className="text-muted">DEMO SENDER: </span>
                <span className="font-mono text-cyan">{userId}</span>
              </div>

              <div>
                <span className="text-muted">DETECTED INTENT: </span>
                <span className="font-mono text-cyan">
                  {verdict?.intent || 'UNSPECIFIED'}
                </span>
              </div>

              {isTransfer && txnDetails && (
                <>
                  {txnDetails.recipient && (
                    <div>
                      <span className="text-muted">RECIPIENT: </span>
                      <span className="font-mono text-green">{txnDetails.recipient}</span>
                    </div>
                  )}
                  {txnDetails.amount && (
                    <div>
                      <span className="text-muted">AMOUNT: </span>
                      <span className="font-mono text-green">{txnDetails.amount} INR</span>
                    </div>
                  )}
                  {txnDetails.memo && (
                    <div>
                      <span className="text-muted">MEMO: </span>
                      <span className="font-mono text-secondary">{txnDetails.memo}</span>
                    </div>
                  )}
                </>
              )}

              {isBalanceInquiry && (
                <div>
                  <span className="text-muted">ACTION: </span>
                  <span className="font-mono text-cyan">
                    Query current balance for account {userId}
                  </span>
                </div>
              )}
            </div>
          </div>

          <div
            style={{
              display: 'flex',
              justifyContent: 'flex-end',
              gap: 12,
              marginTop: 10,
            }}
          >
            <button
              type="button"
              className="btn btn-secondary font-mono"
              onClick={onCancel}
              disabled={isProcessing}
            >
              CANCEL [ESC]
            </button>

            <button
              ref={confirmBtnRef}
              type="button"
              className={isExecutionBoundary ? 'btn btn-danger font-mono' : 'btn btn-execute font-mono'}
              onClick={onConfirm}
              disabled={isProcessing}
            >
              {isProcessing
                ? 'EXECUTING...'
                : isExecutionBoundary
                ? 'CONFIRM DEMO SUBMISSION'
                : 'CONFIRM & EXECUTE'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

