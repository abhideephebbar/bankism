/**
 * Bankism TypeScript Types
 * Derived strictly from backend schemas:
 * backend/app/schemas.py and backend/app/main.py
 */

export type Decision = 'APPROVE' | 'BLOCK';

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ThreatCategory =
  | 'NONE'
  | 'PROMPT_INJECTION'
  | 'ROLEPLAY_JAILBREAK'
  | 'POLICY_OVERRIDE'
  | 'MEMO_INJECTION'
  | 'OBFUSCATION'
  | 'DATA_EXFILTRATION'
  | 'VALIDATION_FAILURE'
  | 'UNSUPPORTED_OPERATION';

export type Intent =
  | 'NONE'
  | 'BALANCE_INQUIRY'
  | 'TRANSFER'
  | 'UNSUPPORTED';

/**
 * Request payload for POST /api/v1/evaluate and POST /api/v1/process.
 * Backend enforces extra="forbid". Only these three fields are accepted.
 * NEVER send decision, risk_level, or intent.
 */
export interface EvaluateRequest {
  message: string;
  memo?: string | null;
  user_id?: string | null;
}

export interface TransactionDetails {
  recipient?: string | null;
  amount?: string | null;
  currency?: string | null;
  memo?: string | null;
}

export interface Verdict {
  request_id: string;
  decision: Decision;
  risk_level: RiskLevel;
  threat_category: ThreatCategory;
  rationale: string;
  intent: Intent;
  transaction_details?: TransactionDetails | null;
  validation_errors: string[];
  signals: string[];
}

export interface ProcessResponse {
  verdict: Verdict;
  action_executed: boolean;
  simulated: boolean;
  transaction_id?: string | null;
  balance?: string | null;
}

export interface HealthResponse {
  status: string;
  service: string;
  simulated: boolean;
  currency: string;
}

/**
 * Response shape for POST /api/v1/demo/users and
 * GET /api/v1/demo/account/{user_id}. The backend is the source of truth:
 * `balance` is the actual current simulated balance, never computed here.
 * `user_id` is a demo selector, NOT an authentication credential.
 */
export interface DemoAccount {
  user_id: string;
  display_name: string;
  simulated: boolean;
  currency: string;
  balance: string;
}

/**
 * UI snapshot of a submitted evaluation request.
 * Used for detecting when live inputs differ from what generated the verdict.
 */
export interface RequestSnapshot {
  message: string;
  memo: string;
  userId: string;
  timestamp: string;
  requestId: number;
}

export type EvaluationUiStatus =
  | 'IDLE'
  | 'IN_FLIGHT'
  | 'SUCCESS'
  | 'REQUEST_REJECTED' // HTTP 422 or other HTTP errors
  | 'SYSTEM_ERROR'; // Network error, timeout, or malformed response

export type ProcessUiStatus =
  | 'IDLE'
  | 'IN_FLIGHT'
  | 'SUCCESS'
  | 'REQUEST_REJECTED' // HTTP 422
  | 'EXECUTION_UNKNOWN' // Timeout or connection drop post-submission
  | 'SYSTEM_ERROR';

