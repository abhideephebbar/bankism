import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { App } from '../App';
import { VerdictPanel } from '../components/VerdictPanel';
import { ProcessResultPanel } from '../components/ProcessResultPanel';
import { AccountSetup } from '../components/AccountSetup';
import { Verdict, ProcessResponse } from '../types/firewall';

const HEALTH = { status: 'ok', service: 'bankism-firewall', simulated: true, currency: 'INR' };

const MOCK_ACCOUNT = {
  user_id: 'user-abc123def456',
  display_name: 'Nisha',
  simulated: true,
  currency: 'INR',
  balance: '1000.00',
};

const MOCK_VERDICT: Verdict = {
  request_id: 'req-mock-1',
  decision: 'APPROVE',
  risk_level: 'LOW',
  threat_category: 'NONE',
  rationale: 'Transfer to a known payee within limits; approved.',
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

const MOCK_PROCESS: ProcessResponse = {
  verdict: MOCK_VERDICT,
  action_executed: true,
  simulated: true,
  transaction_id: 'TXN-000001',
  balance: '500.00',
};

function jsonResponse(body: unknown) {
  return Promise.resolve({ ok: true, json: async () => body });
}

describe('Account creation flow', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    sessionStorage.clear();
  });

  afterEach(() => {
    sessionStorage.clear();
  });

  it('AccountSetup validates name and balance before calling onCreate', async () => {
    const onCreate = vi.fn().mockResolvedValue(undefined);
    render(<AccountSetup onCreate={onCreate} isCreating={false} errorMessage={null} />);

    // Empty submit -> validation error, no API call
    fireEvent.click(screen.getByRole('button', { name: /create simulated account/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/display name/i);
    expect(onCreate).not.toHaveBeenCalled();

    // Bad balances rejected client-side
    fireEvent.change(screen.getByLabelText(/display name/i), { target: { value: 'Nisha' } });
    const balanceInput = screen.getByLabelText(/starting balance/i);
    for (const bad of ['-5', '1e3', '10.999', 'abc']) {
      fireEvent.change(balanceInput, { target: { value: bad } });
      fireEvent.click(screen.getByRole('button', { name: /create simulated account/i }));
      expect(await screen.findByRole('alert')).toHaveTextContent(/starting balance/i);
      expect(onCreate).not.toHaveBeenCalled();
    }

    // Zero balance is allowed (insufficient-funds demo)
    fireEvent.change(balanceInput, { target: { value: '0' } });
    fireEvent.click(screen.getByRole('button', { name: /create simulated account/i }));
    await waitFor(() =>
      expect(onCreate).toHaveBeenCalledWith('Nisha', '0')
    );

    // Disclosure is present
    expect(screen.getByText(/fully simulated/i)).toBeInTheDocument();
  });

  it('App: creates an account through the backend and uses its user_id for evaluate', async () => {
    sessionStorage.setItem('bankism_boot_completed', 'true');

    const calls: { url: string; body: unknown }[] = [];
    globalThis.fetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      if (url.includes('/demo/users') && init?.method === 'POST') {
        calls.push({ url, body: JSON.parse(String(init.body)) });
        return jsonResponse(MOCK_ACCOUNT);
      }
      if (url.includes('/demo/account/')) return jsonResponse(MOCK_ACCOUNT);
      if (url.includes('/health')) return jsonResponse(HEALTH);
      if (url.includes('/api/v1/evaluate')) {
        calls.push({ url, body: JSON.parse(String(init?.body)) });
        return jsonResponse(MOCK_VERDICT);
      }
      return Promise.reject(new Error(`Unexpected fetch: ${url}`));
    });

    render(<App />);

    // Setup screen is the normal flow with no saved account
    fireEvent.change(screen.getByLabelText(/display name/i), { target: { value: 'Nisha' } });
    fireEvent.change(screen.getByLabelText(/starting balance/i), { target: { value: '1000' } });
    fireEvent.click(screen.getByRole('button', { name: /create simulated account/i }));

    // Account summary appears with backend-returned balance
    await waitFor(() =>
      expect(screen.getByText('Nisha')).toBeInTheDocument()
    );
    expect(screen.getByText('1000.00')).toBeInTheDocument();
    expect(screen.getByText('INR')).toBeInTheDocument();

    // Create call used the exact form values
    expect(calls[0].body).toEqual({ display_name: 'Nisha', initial_balance: '1000' });

    // Subsequent evaluate uses the backend-generated user_id
    fireEvent.click(screen.getByRole('button', { name: /evaluate request via firewall/i }));
    await waitFor(() =>
      expect(screen.getByText(/Transfer to a known payee/i)).toBeInTheDocument()
    );
    const evalCall = calls.find((c) => c.url.includes('/api/v1/evaluate'));
    expect(evalCall?.body).toMatchObject({ user_id: 'user-abc123def456' });
  });

  it('App: a saved account that no longer exists asks for a new account', async () => {
    sessionStorage.setItem('bankism_boot_completed', 'true');
    sessionStorage.setItem(
      'bankism_account',
      JSON.stringify({ user_id: 'user-gone000000', display_name: 'Ghost' })
    );

    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/demo/account/')) {
        return Promise.resolve({
          ok: false,
          status: 404,
          json: async () => ({ detail: 'unknown demo account' }),
        });
      }
      if (url.includes('/health')) return jsonResponse(HEALTH);
      return Promise.reject(new Error(`Unexpected fetch: ${url}`));
    });

    render(<App />);

    await waitFor(() =>
      expect(
        screen.getByText(/no longer available/i)
      ).toBeInTheDocument()
    );
    expect(
      screen.getByRole('button', { name: /create simulated account/i })
    ).toBeInTheDocument();
  });

  it('App: can switch back to a created account after using a sample profile', async () => {
    sessionStorage.setItem('bankism_boot_completed', 'true');

    const CREATED = { ...MOCK_ACCOUNT, balance: '750.00' };
    const ALICE = {
      user_id: 'alice',
      display_name: 'Alice',
      simulated: true,
      currency: 'INR',
      balance: '25000.00',
    };

    globalThis.fetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      if (url.includes('/demo/users') && init?.method === 'POST') {
        return jsonResponse(CREATED);
      }
      if (url.endsWith('/demo/account/alice')) return jsonResponse(ALICE);
      if (url.includes('/demo/account/')) return jsonResponse(CREATED);
      if (url.includes('/health')) return jsonResponse(HEALTH);
      if (url.includes('/api/v1/evaluate')) return jsonResponse(MOCK_VERDICT);
      return Promise.reject(new Error(`Unexpected fetch: ${url}`));
    });

    render(<App />);

    // 1. Create an account
    fireEvent.change(screen.getByLabelText(/display name/i), { target: { value: 'Nisha' } });
    fireEvent.change(screen.getByLabelText(/starting balance/i), { target: { value: '750' } });
    fireEvent.click(screen.getByRole('button', { name: /create simulated account/i }));
    await waitFor(() => expect(screen.getByText('Nisha')).toBeInTheDocument());

    // 2. Switch to a sample profile via the About menu
    fireEvent.click(screen.getByRole('button', { name: /^about$/i }));
    fireEvent.click(screen.getByRole('menuitem', { name: /^alice/i }));
    await waitFor(() => expect(screen.getByText('Alice')).toBeInTheDocument());

    // 3. Switch BACK to the created account via "Your accounts"
    fireEvent.click(screen.getByRole('button', { name: /^about$/i }));
    fireEvent.click(screen.getByRole('menuitem', { name: /nisha/i }));
    await waitFor(() => expect(screen.getByText('Nisha')).toBeInTheDocument());
    // Balance comes from the backend response for that account
    expect(screen.getByText('750.00')).toBeInTheDocument();
  });

  it('App: log out returns to the setup screen without losing the used-account list', async () => {
    sessionStorage.setItem('bankism_boot_completed', 'true');

    globalThis.fetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      if (url.includes('/demo/users') && init?.method === 'POST') {
        return jsonResponse(MOCK_ACCOUNT);
      }
      if (url.includes('/demo/account/')) return jsonResponse(MOCK_ACCOUNT);
      if (url.includes('/health')) return jsonResponse(HEALTH);
      return Promise.reject(new Error(`Unexpected fetch: ${url}`));
    });

    render(<App />);

    fireEvent.change(screen.getByLabelText(/display name/i), { target: { value: 'Nisha' } });
    fireEvent.change(screen.getByLabelText(/starting balance/i), { target: { value: '1000' } });
    fireEvent.click(screen.getByRole('button', { name: /create simulated account/i }));
    await waitFor(() => expect(screen.getByText('Nisha')).toBeInTheDocument());

    // About -> Log out -> setup screen
    fireEvent.click(screen.getByRole('button', { name: /^about$/i }));
    fireEvent.click(screen.getByRole('menuitem', { name: /^log out$/i }));
    expect(
      await screen.findByRole('button', { name: /create simulated account/i })
    ).toBeInTheDocument();

    // The logged-out account is offered for quick demo log-in
    expect(screen.getByText(/welcome back/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /log in as nisha/i }));
    await waitFor(() => expect(screen.getByText('Nisha')).toBeInTheDocument());
  });
});

describe('Raw JSON display and copy', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('VerdictPanel: Raw JSON is collapsed by default and reveals the exact response', () => {
    render(
      <VerdictPanel
        verdict={MOCK_VERDICT}
        uiStatus="SUCCESS"
        errorMessage={null}
        isStale={false}
        rawResponseJson={MOCK_VERDICT}
      />
    );

    // Collapsed by default: JSON content not visible
    expect(screen.queryByText(/req-mock-1/)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /raw json/i }));

    const pre = screen.getByLabelText(/raw json, evaluation response/i);
    expect(pre.tagName).toBe('PRE');
    const shown = JSON.parse(pre.textContent || '{}') as Verdict;
    expect(shown).toEqual(MOCK_VERDICT); // exact response, all fields
  });

  it('Copy JSON copies the exact response and shows a copied state', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    });

    render(
      <VerdictPanel
        verdict={MOCK_VERDICT}
        uiStatus="SUCCESS"
        errorMessage={null}
        isStale={false}
        rawResponseJson={MOCK_VERDICT}
      />
    );

    fireEvent.click(screen.getByRole('button', { name: /raw json/i }));
    fireEvent.click(screen.getByRole('button', { name: /copy json/i }));

    await waitFor(() =>
      expect(writeText).toHaveBeenCalledWith(JSON.stringify(MOCK_VERDICT, null, 2))
    );
    expect(await screen.findByText('Copied')).toBeInTheDocument();
  });

  it('Copy failure shows an honest error state, never fabricated content', async () => {
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: vi.fn().mockRejectedValue(new Error('denied')) },
      configurable: true,
    });

    render(
      <VerdictPanel
        verdict={MOCK_VERDICT}
        uiStatus="SUCCESS"
        errorMessage={null}
        isStale={false}
        rawResponseJson={MOCK_VERDICT}
      />
    );

    fireEvent.click(screen.getByRole('button', { name: /raw json/i }));
    fireEvent.click(screen.getByRole('button', { name: /copy json/i }));

    expect(await screen.findByText(/copy failed/i)).toBeInTheDocument();
  });

  it('Process JSON is displayed separately from evaluation JSON', () => {
    const { container: evalContainer } = render(
      <VerdictPanel
        verdict={MOCK_VERDICT}
        uiStatus="SUCCESS"
        errorMessage={null}
        isStale={false}
        rawResponseJson={MOCK_VERDICT}
      />
    );
    const { container: procContainer } = render(
      <ProcessResultPanel
        processResult={MOCK_PROCESS}
        uiStatus="SUCCESS"
        errorMessage={null}
      />
    );

    expect(
      evalContainer.querySelector('[data-raw-json="evaluation response"]')
    ).not.toBeNull();
    expect(
      procContainer.querySelector('[data-raw-json="process response"]')
    ).not.toBeNull();

    // Both collapsed by default
    expect(evalContainer.querySelector('pre')).toBeNull();
    expect(procContainer.querySelector('pre')).toBeNull();
  });
});
