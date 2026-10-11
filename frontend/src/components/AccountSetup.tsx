import React, { useState } from 'react';
import { ApiHttpError, ApiSystemError } from '../services/api';

interface AccountSetupProps {
  onCreate: (displayName: string, initialBalance: string) => Promise<void>;
  isCreating: boolean;
  errorMessage: string | null;
  /** Shown when a previously saved account no longer exists on the backend. */
  missingAccountNotice?: boolean;
}

const BALANCE_RE = /^\d+(\.\d{1,2})?$/;

export const AccountSetup: React.FC<AccountSetupProps> = ({
  onCreate,
  isCreating,
  errorMessage,
  missingAccountNotice = false,
}) => {
  const [displayName, setDisplayName] = useState('');
  const [initialBalance, setInitialBalance] = useState('');
  const [validationError, setValidationError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const name = displayName.trim();
    if (name.length < 1 || name.length > 64) {
      setValidationError('Please enter a display name (1–64 characters).');
      return;
    }

    const balance = initialBalance.trim();
    if (!BALANCE_RE.test(balance)) {
      setValidationError(
        'Starting balance must be 0 or more, in INR, with at most two decimal places (e.g. 25000 or 100.50).'
      );
      return;
    }

    setValidationError(null);
    await onCreate(name, balance);
  };

  const shownError = validationError || errorMessage;
  const isValidation = validationError !== null;
  const isServerError = !isValidation && errorMessage !== null;

  return (
    <div
      className="bankism-panel"
      style={{
        maxWidth: 440,
        width: '100%',
        margin: '0 auto',
        animation: 'fadeUp 520ms cubic-bezier(0.22, 1, 0.36, 1) both',
      }}
      aria-label="Create a simulated account"
    >
      <div className="panel-header">
        <span className="panel-title">Create your simulated account</span>
      </div>

      {missingAccountNotice && (
        <div
          role="status"
          style={{
            marginBottom: 16,
            padding: '10px 12px',
            borderRadius: 8,
            border: '1px solid rgba(255, 170, 0, 0.35)',
            background: 'rgba(30, 22, 8, 0.7)',
            color: 'var(--color-amber)',
            fontSize: 12,
            lineHeight: 1.5,
          }}
        >
          Your previous simulated account is no longer available — the demo store
          resets when the server restarts. Create a new one to continue.
        </div>
      )}

      <form onSubmit={handleSubmit} noValidate>
        <div className="input-group">
          <div className="input-label">
            <label htmlFor="account-name-input">Display name</label>
          </div>
          <input
            id="account-name-input"
            type="text"
            className="bankism-input"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder="e.g. Nisha"
            maxLength={64}
            disabled={isCreating}
            autoComplete="off"
          />
        </div>

        <div className="input-group">
          <div className="input-label">
            <label htmlFor="account-balance-input">Starting balance (INR)</label>
          </div>
          <input
            id="account-balance-input"
            type="text"
            inputMode="decimal"
            className="bankism-input"
            value={initialBalance}
            onChange={(e) => setInitialBalance(e.target.value)}
            placeholder="e.g. 25000 or 0"
            maxLength={15}
            disabled={isCreating}
            autoComplete="off"
          />
        </div>

        {shownError && (
          <div
            role="alert"
            style={{
              marginBottom: 14,
              padding: '9px 12px',
              borderRadius: 8,
              fontSize: 12,
              lineHeight: 1.5,
              border: `1px solid ${
                isValidation ? 'rgba(255, 170, 0, 0.4)' : 'rgba(255, 42, 95, 0.4)'
              }`,
              background: isValidation
                ? 'rgba(30, 22, 8, 0.7)'
                : 'rgba(40, 10, 18, 0.6)',
              color: isValidation ? 'var(--color-amber)' : '#ff8aa5',
            }}
          >
            {isServerError && 'The account could not be created. '}
            {shownError}
          </div>
        )}

        <button
          type="submit"
          className="btn btn-primary"
          disabled={isCreating}
          style={{ width: '100%' }}
        >
          {isCreating ? 'Creating…' : 'Create Simulated Account'}
        </button>
      </form>

      <p
        className="text-muted"
        style={{ fontSize: 11, lineHeight: 1.6, marginTop: 14 }}
      >
        This account and its balance are fully simulated. No real money is
        involved, and the generated account ID is a demo selector — not a login
        or an authentication credential.
      </p>
    </div>
  );
};

/** Helper for callers to word server-side failures without leaking internals. */
export function accountCreationErrorMessage(err: unknown): string {
  if (err instanceof ApiHttpError) {
    return err.status === 422
      ? err.detail
      : `The service rejected the request (${err.detail}).`;
  }
  if (err instanceof ApiSystemError) {
    return err.message;
  }
  return err instanceof Error ? err.message : 'Unexpected account creation failure';
}
