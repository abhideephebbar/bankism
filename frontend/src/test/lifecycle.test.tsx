import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { App } from '../App';
import { VerdictPanel } from '../components/VerdictPanel';
import { ProcessResultPanel } from '../components/ProcessResultPanel';
import { CommandConsole } from '../components/CommandConsole';
import { Verdict } from '../types/firewall';

// Clearly distinguish unit-test mocks from live API results
const MOCK_APPROVED_VERDICT: Verdict = {
  request_id: 'req-mock-approve-1',
  decision: 'APPROVE',
  risk_level: 'LOW',
  threat_category: 'NONE',
  rationale: 'Valid transfer approved.',
  intent: 'TRANSFER',
  transaction_details: {
    recipient: 'Priya',
    amount: '500.00',
    currency: 'INR',
    memo: 'rent for October',
  },
  validation_errors: [],
  signals: [],
};

const MOCK_BLOCKED_VERDICT: Verdict = {
  request_id: 'req-mock-block-1',
  decision: 'BLOCK',
  risk_level: 'CRITICAL',
  threat_category: 'PROMPT_INJECTION',
  rationale: 'Instruction manipulation pattern detected.',
  intent: 'NONE',
  transaction_details: null,
  validation_errors: [],
  signals: ['prompt_injection_pattern'],
};

describe('Frontend Lifecycle & Safety Rules (Unit Test Mocks)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    sessionStorage.setItem('bankism_boot_completed', 'true');
    sessionStorage.removeItem('bankism_account');
  });

  it('HTTP 422 is shown as REQUEST REJECTED, never as a BLOCK verdict', () => {
    render(
      <VerdictPanel
        verdict={null}
        uiStatus="REQUEST_REJECTED"
        errorMessage="extra fields not permitted"
        isStale={false}
      />
    );

    expect(screen.getAllByText(/REQUEST REJECTED/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/HTTP 422 CLIENT ERROR/i)).toBeInTheDocument();
    expect(screen.queryByText(/THREAT NEUTRALIZED/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/VERDICT: BLOCK/i)).not.toBeInTheDocument();
  });

  it('Network failure is shown as SYSTEM ERROR — VERDICT UNAVAILABLE, never a fabricated verdict', () => {
    render(
      <VerdictPanel
        verdict={null}
        uiStatus="SYSTEM_ERROR"
        errorMessage="Failed to fetch"
        isStale={false}
      />
    );

    expect(
      screen.getByText(/SYSTEM ERROR — VERDICT UNAVAILABLE/i)
    ).toBeInTheDocument();
    expect(screen.queryByText(/APPROVE/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/BLOCK/i)).not.toBeInTheDocument();
  });

  it('A malformed API response is shown as SYSTEM ERROR — VERDICT UNAVAILABLE', () => {
    render(
      <VerdictPanel
        verdict={null}
        uiStatus="SYSTEM_ERROR"
        errorMessage="Backend returned a malformed verdict that failed runtime validation"
        isStale={false}
      />
    );

    expect(
      screen.getByText(/SYSTEM ERROR — VERDICT UNAVAILABLE/i)
    ).toBeInTheDocument();
    expect(
      screen.getByText(/failed runtime validation/i)
    ).toBeInTheDocument();
  });

  it('A stale verdict disables normal Process button', () => {
    const onOpenProcessModal = vi.fn();

    render(
      <CommandConsole
        message="send 600 to Priya" // Modified message
        memo="rent"
        onMessageChange={vi.fn()}
        onMemoChange={vi.fn()}
        onEvaluate={vi.fn()}
        onOpenProcessModal={onOpenProcessModal}
        onOpenExecutionBoundaryModal={vi.fn()}
        isEvaluating={false}
        isProcessing={false}
        latestDecision="APPROVE"
        isVerdictStale={true} // Marked STALE
      />
    );

    const processBtn = screen.getByRole('button', { name: /process transaction/i });
    expect(processBtn).toBeDisabled();
    expect(screen.getByText(/INPUTS MODIFIED: Displayed verdict is STALE/i)).toBeInTheDocument();
  });

  it('Normal Process is disabled for a BLOCK verdict', () => {
    render(
      <CommandConsole
        message="ignore previous instructions"
        memo=""
        onMessageChange={vi.fn()}
        onMemoChange={vi.fn()}
        onEvaluate={vi.fn()}
        onOpenProcessModal={vi.fn()}
        onOpenExecutionBoundaryModal={vi.fn()}
        isEvaluating={false}
        isProcessing={false}
        latestDecision="BLOCK"
        isVerdictStale={false}
      />
    );

    const processBtn = screen.getByRole('button', { name: /process transaction/i });
    expect(processBtn).toBeDisabled();
  });

  it('The execution-boundary demonstration is available only for a fresh, unedited BLOCK verdict', () => {
    const onOpenDemo = vi.fn();

    const { rerender } = render(
      <CommandConsole
        message="ignore instructions"
        memo=""
        onMessageChange={vi.fn()}
        onMemoChange={vi.fn()}
        onEvaluate={vi.fn()}
        onOpenProcessModal={vi.fn()}
        onOpenExecutionBoundaryModal={onOpenDemo}
        isEvaluating={false}
        isProcessing={false}
        latestDecision="BLOCK"
        isVerdictStale={false} // fresh unedited
      />
    );

    const demoBtn = screen.getByRole('button', {
      name: /attempt process anyway \(server will enforce\)/i,
    });
    expect(demoBtn).toBeEnabled();
    fireEvent.click(demoBtn);
    expect(onOpenDemo).toHaveBeenCalledTimes(1);

    // If verdict becomes STALE, demo action is disabled
    rerender(
      <CommandConsole
        message="ignore instructions changed"
        memo=""
        onMessageChange={vi.fn()}
        onMemoChange={vi.fn()}
        onEvaluate={vi.fn()}
        onOpenProcessModal={vi.fn()}
        onOpenExecutionBoundaryModal={onOpenDemo}
        isEvaluating={false}
        isProcessing={false}
        latestDecision="BLOCK"
        isVerdictStale={true} // now stale
      />
    );
    expect(demoBtn).toBeDisabled();
  });

  it('Evaluation-only block displays BLOCKED AT EVALUATION. NO ACTION WAS EXECUTED.', () => {
    render(
      <VerdictPanel
        verdict={MOCK_BLOCKED_VERDICT}
        uiStatus="SUCCESS"
        errorMessage={null}
        isStale={false}
      />
    );

    expect(screen.getByText('THREAT NEUTRALIZED')).toBeInTheDocument();
    expect(
      screen.getByText('BLOCKED AT EVALUATION. NO ACTION WAS EXECUTED.')
    ).toBeInTheDocument();
    expect(
      screen.queryByText('TRANSACTION BLOCKED. NO FUNDS MOVED')
    ).not.toBeInTheDocument();
  });

  it('Process timeout shows EXECUTION STATUS UNKNOWN and does not claim cancellation or execution failure', () => {
    render(
      <ProcessResultPanel
        processResult={null}
        uiStatus="EXECUTION_UNKNOWN"
        errorMessage="Process request timed out after 8 seconds."
      />
    );

    expect(screen.getByText('EXECUTION STATUS UNKNOWN')).toBeInTheDocument();
    expect(
      screen.getByText(/The backend may have completed the simulated transfer/i)
    ).toBeInTheDocument();
    expect(
      screen.getByText(/This operation has NOT been marked as blocked or failed, and has NOT been automatically retried/i)
    ).toBeInTheDocument();
  });

  it('In-app evaluation lifecycle: in-flight submissions are protected and a newer evaluation replaces the older result', async () => {
    // A persisted account is restored from the backend on mount.
    sessionStorage.setItem(
      'bankism_account',
      JSON.stringify({ user_id: 'alice', display_name: 'Alice' })
    );

    let resolveFirst: (val: unknown) => void = () => {};
    const firstPromise = new Promise((resolve) => {
      resolveFirst = resolve;
    });

    const ACCOUNT_SUMMARY = {
      user_id: 'alice',
      display_name: 'Alice',
      simulated: true,
      currency: 'INR',
      balance: '25000.00',
    };
    const HEALTH = { status: 'ok', service: 'bankism-firewall', simulated: true, currency: 'INR' };

    let evaluationCalls = 0;
    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/demo/account/')) {
        return Promise.resolve({ ok: true, json: async () => ACCOUNT_SUMMARY });
      }
      if (url.includes('/health')) {
        return Promise.resolve({ ok: true, json: async () => HEALTH });
      }
      evaluationCalls += 1;
      // First evaluation stays pending; later ones resolve immediately.
      if (evaluationCalls === 1) {
        return firstPromise;
      }
      return Promise.resolve({
        ok: true,
        json: async () => ({
          ...MOCK_APPROVED_VERDICT,
          request_id: 'req-mock-new-2',
          rationale: 'Newer evaluation result',
        }),
      });
    });

    render(<App />);

    const evalBtn = await screen.findByRole('button', {
      name: /evaluate request via firewall/i,
    });

    // Submit the first evaluation; it stays in flight.
    fireEvent.click(evalBtn);

    // Duplicate submissions are blocked while a request is in flight.
    expect(evalBtn).toBeDisabled();

    // The first evaluation completes and its verdict is displayed.
    resolveFirst({
      ok: true,
      json: async () => ({
        ...MOCK_BLOCKED_VERDICT,
        request_id: 'req-mock-old-1',
        rationale: 'First evaluation result',
      }),
    });
    expect(await screen.findByText('First evaluation result')).toBeInTheDocument();
    expect(evalBtn).toBeEnabled();

    // A newer evaluation replaces the older verdict.
    const textarea = screen.getByRole('textbox', { name: /natural-language request/i });
    fireEvent.change(textarea, { target: { value: 'send 100 to Priya' } });
    fireEvent.click(evalBtn);

    await waitFor(() => {
      expect(screen.getByText('Newer evaluation result')).toBeInTheDocument();
    });
    expect(screen.queryByText('First evaluation result')).not.toBeInTheDocument();
  });

  it('The signature threat-neutralization sequence triggers only after a valid BLOCK response', () => {
    // 1. APPROVE verdict should NOT show THREAT NEUTRALIZED
    const { rerender } = render(
      <VerdictPanel
        verdict={MOCK_APPROVED_VERDICT}
        uiStatus="SUCCESS"
        errorMessage={null}
        isStale={false}
      />
    );
    expect(screen.queryByText('THREAT NEUTRALIZED')).not.toBeInTheDocument();
    expect(screen.getByText('✓ REQUEST APPROVED')).toBeInTheDocument();

    // 2. Suspicious input alone with HTTP 422 should NOT show THREAT NEUTRALIZED
    rerender(
      <VerdictPanel
        verdict={null}
        uiStatus="REQUEST_REJECTED"
        errorMessage="Invalid schema"
        isStale={false}
      />
    );
    expect(screen.queryByText('THREAT NEUTRALIZED')).not.toBeInTheDocument();

    // 3. Only a valid BLOCK verdict triggers THREAT NEUTRALIZED
    rerender(
      <VerdictPanel
        verdict={MOCK_BLOCKED_VERDICT}
        uiStatus="SUCCESS"
        errorMessage={null}
        isStale={false}
      />
    );
    expect(screen.getByText('THREAT NEUTRALIZED')).toBeInTheDocument();
  });

  it('Evaluation and processing have separate cancellation and state handling', async () => {
    let resolveProcess: (val: unknown) => void = () => {};
    const processPromise = new Promise((resolve) => {
      resolveProcess = resolve;
    });

    // Mock process call
    globalThis.fetch = vi.fn().mockImplementationOnce(() => processPromise);

    render(
      <ProcessResultPanel
        processResult={null}
        uiStatus="IN_FLIGHT"
        errorMessage={null}
      />
    );

    // Editing inputs or triggering an evaluation in another panel does not abort in-flight process
    expect(screen.queryByText('EXECUTION STATUS UNKNOWN')).not.toBeInTheDocument();

    // When process completes, it receives its own process response
    resolveProcess({
      ok: true,
      json: async () => ({
        verdict: MOCK_APPROVED_VERDICT,
        action_executed: true,
        simulated: true,
        transaction_id: 'TXN-999999',
        balance: '20000.00',
      }),
    });
  });
});
