import {
  DemoAccount,
  EvaluateRequest,
  HealthResponse,
  ProcessResponse,
  Verdict,
} from '../types/firewall';
import {
  isDemoAccount,
  isHealthResponse,
  isProcessResponse,
  isVerdict,
} from '../utils/validation';

export const API_BASE_URL =
  (import.meta.env.VITE_API_BASE_URL as string | undefined)?.trim() || 'http://127.0.0.1:8000';

export class ApiHttpError extends Error {
  readonly status: number;
  readonly detail: string;

  constructor(status: number, message: string, detail?: string) {
    super(message);
    this.name = 'ApiHttpError';
    this.status = status;
    this.detail = detail || message;
  }
}

export type SystemErrorKind = 'TIMEOUT' | 'NETWORK' | 'MALFORMED_RESPONSE';

export class ApiSystemError extends Error {
  readonly kind: SystemErrorKind;

  constructor(kind: SystemErrorKind, message: string) {
    super(message);
    this.name = 'ApiSystemError';
    this.kind = kind;
  }
}

/**
 * Strips any extra fields to strictly adhere to backend extra="forbid".
 * Never includes decision, risk_level, intent or unexpected properties.
 */
export function buildEvaluatePayload(
  message: string,
  memo?: string | null,
  userId?: string | null
): EvaluateRequest {
  const payload: EvaluateRequest = {
    message: message.trim(),
  };

  const trimmedMemo = memo?.trim();
  if (trimmedMemo) {
    payload.memo = trimmedMemo;
  }

  const trimmedUser = userId?.trim();
  if (trimmedUser) {
    payload.user_id = trimmedUser;
  }

  return payload;
}

/**
 * Health check probe: GET /health. Generous timeout so a hosted instance
 * that is waking from an idle sleep can still answer before we give up.
 */
export async function checkHealth(signal?: AbortSignal): Promise<HealthResponse> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 25000);

  const combinedSignal = signal
    ? createMergedAbortSignal(signal, controller.signal)
    : controller.signal;

  try {
    const response = await fetch(`${API_BASE_URL}/health`, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
      },
      signal: combinedSignal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new ApiHttpError(
        response.status,
        `Health probe failed with HTTP ${response.status}`
      );
    }

    const data = await response.json();
    if (!isHealthResponse(data)) {
      throw new ApiSystemError(
        'MALFORMED_RESPONSE',
        'Backend returned an unexpected health response structure'
      );
    }

    return data;
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    if (err instanceof ApiHttpError || err instanceof ApiSystemError) {
      throw err;
    }
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new ApiSystemError('TIMEOUT', 'Health check timed out after 4 seconds');
    }
    throw new ApiSystemError(
      'NETWORK',
      err instanceof Error ? err.message : 'Network connection failure during health probe'
    );
  }
}

/**
 * Evaluate request: POST /api/v1/evaluate with ~8 second timeout.
 * Re-evaluates without side-effects. Returns fresh Verdict.
 */
export async function evaluateRequest(
  payload: EvaluateRequest,
  signal?: AbortSignal
): Promise<Verdict> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000);

  const combinedSignal = signal
    ? createMergedAbortSignal(signal, controller.signal)
    : controller.signal;

  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/evaluate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
      signal: combinedSignal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      let detail = `HTTP ${response.status} ${response.statusText}`;
      try {
        const errorData = await response.json();
        if (errorData?.detail) {
          detail = typeof errorData.detail === 'string'
            ? errorData.detail
            : JSON.stringify(errorData.detail);
        }
      } catch {
        // use fallback detail
      }
      throw new ApiHttpError(response.status, `Request rejected by backend: ${detail}`, detail);
    }

    const data = await response.json();
    if (!isVerdict(data)) {
      throw new ApiSystemError(
        'MALFORMED_RESPONSE',
        'Backend returned a malformed verdict that failed runtime validation'
      );
    }

    return data;
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    if (err instanceof ApiHttpError || err instanceof ApiSystemError) {
      throw err;
    }
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new ApiSystemError('TIMEOUT', 'Evaluation request timed out after 8 seconds');
    }
    throw new ApiSystemError(
      'NETWORK',
      err instanceof Error ? err.message : 'Network connection failure during evaluation'
    );
  }
}

/**
 * Process request: POST /api/v1/process with ~8 second timeout.
 * Submits for server-side re-evaluation and execution.
 */
export async function processRequest(
  payload: EvaluateRequest,
  signal?: AbortSignal
): Promise<ProcessResponse> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000);

  const combinedSignal = signal
    ? createMergedAbortSignal(signal, controller.signal)
    : controller.signal;

  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/process`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
      signal: combinedSignal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      let detail = `HTTP ${response.status} ${response.statusText}`;
      try {
        const errorData = await response.json();
        if (errorData?.detail) {
          detail = typeof errorData.detail === 'string'
            ? errorData.detail
            : JSON.stringify(errorData.detail);
        }
      } catch {
        // fallback
      }
      throw new ApiHttpError(response.status, `Process request rejected: ${detail}`, detail);
    }

    const data = await response.json();
    if (!isProcessResponse(data)) {
      throw new ApiSystemError(
        'MALFORMED_RESPONSE',
        'Backend returned a malformed process response that failed runtime validation'
      );
    }

    return data;
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    if (err instanceof ApiHttpError || err instanceof ApiSystemError) {
      throw err;
    }
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new ApiSystemError('TIMEOUT', 'Process request timed out after 8 seconds');
    }
    throw new ApiSystemError(
      'NETWORK',
      err instanceof Error ? err.message : 'Network failure during process execution'
    );
  }
}

function createMergedAbortSignal(s1: AbortSignal, s2: AbortSignal): AbortSignal {
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  if (s1.aborted || s2.aborted) {
    controller.abort();
    return controller.signal;
  }
  s1.addEventListener('abort', onAbort, { once: true });
  s2.addEventListener('abort', onAbort, { once: true });
  return controller.signal;
}

/**
 * Create a simulated demo account: POST /api/v1/demo/users.
 * The backend generates the user ID and owns the balance. A 422 means the
 * submitted values were rejected; the caller surfaces the detail verbatim.
 */
export async function createDemoAccount(
  displayName: string,
  initialBalance: string
): Promise<DemoAccount> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000);

  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/demo/users`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        display_name: displayName.trim(),
        initial_balance: initialBalance.trim(),
      }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      let detail = `HTTP ${response.status} ${response.statusText}`;
      try {
        const errorData = await response.json();
        if (errorData?.detail) {
          detail = typeof errorData.detail === 'string'
            ? errorData.detail
            : JSON.stringify(errorData.detail);
        }
      } catch {
        // use fallback detail
      }
      throw new ApiHttpError(response.status, `Account creation rejected: ${detail}`, detail);
    }

    const data = await response.json();
    if (!isDemoAccount(data)) {
      throw new ApiSystemError(
        'MALFORMED_RESPONSE',
        'Backend returned a malformed account response that failed runtime validation'
      );
    }

    return data;
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    if (err instanceof ApiHttpError || err instanceof ApiSystemError) {
      throw err;
    }
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new ApiSystemError('TIMEOUT', 'Account creation timed out after 8 seconds');
    }
    throw new ApiSystemError(
      'NETWORK',
      err instanceof Error ? err.message : 'Network connection failure during account creation'
    );
  }
}

/**
 * Fetch one simulated account summary: GET /api/v1/demo/account/{user_id}.
 * Returns the backend's current balance. HTTP 404 (unknown account) surfaces
 * as ApiHttpError with status 404 so the caller can ask for a new account.
 */
export async function fetchAccountSummary(
  userId: string,
  signal?: AbortSignal
): Promise<DemoAccount> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000);

  const combinedSignal = signal
    ? createMergedAbortSignal(signal, controller.signal)
    : controller.signal;

  try {
    const response = await fetch(
      `${API_BASE_URL}/api/v1/demo/account/${encodeURIComponent(userId)}`,
      {
        method: 'GET',
        headers: {
          Accept: 'application/json',
        },
        signal: combinedSignal,
      }
    );

    clearTimeout(timeoutId);

    if (!response.ok) {
      let detail = `HTTP ${response.status} ${response.statusText}`;
      try {
        const errorData = await response.json();
        if (errorData?.detail) {
          detail = typeof errorData.detail === 'string'
            ? errorData.detail
            : JSON.stringify(errorData.detail);
        }
      } catch {
        // use fallback detail
      }
      throw new ApiHttpError(response.status, `Account lookup failed: ${detail}`, detail);
    }

    const data = await response.json();
    if (!isDemoAccount(data)) {
      throw new ApiSystemError(
        'MALFORMED_RESPONSE',
        'Backend returned a malformed account response that failed runtime validation'
      );
    }

    return data;
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    if (err instanceof ApiHttpError || err instanceof ApiSystemError) {
      throw err;
    }
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new ApiSystemError('TIMEOUT', 'Account lookup timed out after 8 seconds');
    }
    throw new ApiSystemError(
      'NETWORK',
      err instanceof Error ? err.message : 'Network connection failure during account lookup'
    );
  }
}

