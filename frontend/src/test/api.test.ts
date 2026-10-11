import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  ApiHttpError,
  ApiSystemError,
  buildEvaluatePayload,
  evaluateRequest,
  processRequest,
} from '../services/api';

describe('API Client & Request Safety (Unit Test Mocks)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('buildEvaluatePayload sends only allowed fields and forbids extra attributes', () => {
    const payload = buildEvaluatePayload('send 500 to Priya', 'rent', 'alice');
    expect(payload).toEqual({
      message: 'send 500 to Priya',
      memo: 'rent',
      user_id: 'alice',
    });

    // Verify forbidden properties are never present
    const rawKeys = Object.keys(payload);
    expect(rawKeys).not.toContain('decision');
    expect(rawKeys).not.toContain('risk_level');
    expect(rawKeys).not.toContain('intent');
  });

  it('buildEvaluatePayload omits empty memo and user_id gracefully', () => {
    const payload = buildEvaluatePayload('check my balance', '   ', '');
    expect(payload).toEqual({
      message: 'check my balance',
    });
    expect(payload.memo).toBeUndefined();
    expect(payload.user_id).toBeUndefined();
  });

  it('evaluateRequest resolves valid 200 verdict response', async () => {
    const mockVerdict = {
      request_id: 'req-mock-1',
      decision: 'APPROVE',
      risk_level: 'LOW',
      threat_category: 'NONE',
      rationale: 'Valid transfer approved.',
      intent: 'TRANSFER',
      transaction_details: {
        recipient: 'Priya',
        amount: '500.00',
        currency: 'INR',
        memo: 'rent',
      },
      validation_errors: [],
      signals: [],
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockVerdict,
    });

    const result = await evaluateRequest({ message: 'send 500 to Priya' });
    expect(result).toEqual(mockVerdict);
    expect(result.decision).toBe('APPROVE');
  });

  it('evaluateRequest throws ApiHttpError on HTTP 422', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 422,
      statusText: 'Unprocessable Entity',
      json: async () => ({
        detail: [
          {
            loc: ['body', 'decision'],
            msg: 'extra fields not permitted',
            type: 'extra_forbidden',
          },
        ],
      }),
    });

    await expect(
      evaluateRequest({ message: 'send 500 to Priya' })
    ).rejects.toThrow(ApiHttpError);
  });

  it('evaluateRequest throws ApiSystemError on malformed 200 response', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        corrupted: true,
      }),
    });

    await expect(
      evaluateRequest({ message: 'send 500 to Priya' })
    ).rejects.toThrow(ApiSystemError);
  });

  it('evaluateRequest throws ApiSystemError on network failure', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('Failed to fetch'));

    await expect(
      evaluateRequest({ message: 'send 500 to Priya' })
    ).rejects.toThrow(ApiSystemError);
  });

  it('processRequest resolves valid ProcessResponse', async () => {
    const mockProcessResponse = {
      verdict: {
        request_id: 'req-mock-proc',
        decision: 'APPROVE',
        risk_level: 'LOW',
        threat_category: 'NONE',
        rationale: 'Transfer approved',
        intent: 'TRANSFER',
        transaction_details: {
          recipient: 'Priya',
          amount: '500.00',
          currency: 'INR',
        },
        validation_errors: [],
        signals: [],
      },
      action_executed: true,
      simulated: true,
      transaction_id: 'TXN-000001',
      balance: '24500.00',
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockProcessResponse,
    });

    const result = await processRequest({ message: 'send 500 to Priya' });
    expect(result.action_executed).toBe(true);
    expect(result.transaction_id).toBe('TXN-000001');
    expect(result.balance).toBe('24500.00');
  });

  it('processRequest throws ApiSystemError on timeout', async () => {
    const abortErr = new DOMException('The operation was aborted.', 'AbortError');
    globalThis.fetch = vi.fn().mockRejectedValue(abortErr);

    try {
      await processRequest({ message: 'send 500 to Priya' });
      expect.fail('Should have thrown');
    } catch (err: unknown) {
      expect(err).toBeInstanceOf(ApiSystemError);
      expect((err as ApiSystemError).kind).toBe('TIMEOUT');
    }
  });
});
