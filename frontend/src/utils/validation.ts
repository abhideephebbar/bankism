import {
  Decision,
  DemoAccount,
  HealthResponse,
  Intent,
  ProcessResponse,
  RiskLevel,
  ThreatCategory,
  TransactionDetails,
  Verdict,
} from '../types/firewall';

const VALID_DECISIONS: ReadonlySet<string> = new Set<Decision>(['APPROVE', 'BLOCK']);

const VALID_RISK_LEVELS: ReadonlySet<string> = new Set<RiskLevel>([
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL',
]);

const VALID_THREAT_CATEGORIES: ReadonlySet<string> = new Set<ThreatCategory>([
  'NONE',
  'PROMPT_INJECTION',
  'ROLEPLAY_JAILBREAK',
  'POLICY_OVERRIDE',
  'MEMO_INJECTION',
  'OBFUSCATION',
  'DATA_EXFILTRATION',
  'VALIDATION_FAILURE',
  'UNSUPPORTED_OPERATION',
]);

const VALID_INTENTS: ReadonlySet<string> = new Set<Intent>([
  'NONE',
  'BALANCE_INQUIRY',
  'TRANSFER',
  'UNSUPPORTED',
]);

export function isDecision(val: unknown): val is Decision {
  return typeof val === 'string' && VALID_DECISIONS.has(val);
}

export function isRiskLevel(val: unknown): val is RiskLevel {
  return typeof val === 'string' && VALID_RISK_LEVELS.has(val);
}

export function isThreatCategory(val: unknown): val is ThreatCategory {
  return typeof val === 'string' && VALID_THREAT_CATEGORIES.has(val);
}

export function isIntent(val: unknown): val is Intent {
  return typeof val === 'string' && VALID_INTENTS.has(val);
}

export function isTransactionDetails(val: unknown): val is TransactionDetails {
  if (val === null || val === undefined) return true;
  if (typeof val !== 'object') return false;
  const obj = val as Record<string, unknown>;

  const checkOptString = (field: unknown) =>
    field === undefined || field === null || typeof field === 'string';

  return (
    checkOptString(obj.recipient) &&
    checkOptString(obj.amount) &&
    checkOptString(obj.currency) &&
    checkOptString(obj.memo)
  );
}

export function isVerdict(val: unknown): val is Verdict {
  if (!val || typeof val !== 'object') return false;
  const obj = val as Record<string, unknown>;

  if (typeof obj.request_id !== 'string' || obj.request_id.trim() === '') return false;
  if (!isDecision(obj.decision)) return false;
  if (!isRiskLevel(obj.risk_level)) return false;
  if (!isThreatCategory(obj.threat_category)) return false;
  if (typeof obj.rationale !== 'string') return false;
  if (!isIntent(obj.intent)) return false;

  if (obj.transaction_details !== undefined && obj.transaction_details !== null) {
    if (!isTransactionDetails(obj.transaction_details)) return false;
  }

  if (
    !Array.isArray(obj.validation_errors) ||
    !obj.validation_errors.every((e) => typeof e === 'string')
  ) {
    return false;
  }

  if (!Array.isArray(obj.signals) || !obj.signals.every((s) => typeof s === 'string')) {
    return false;
  }

  return true;
}

export function isProcessResponse(val: unknown): val is ProcessResponse {
  if (!val || typeof val !== 'object') return false;
  const obj = val as Record<string, unknown>;

  if (!isVerdict(obj.verdict)) return false;
  if (typeof obj.action_executed !== 'boolean') return false;
  if (typeof obj.simulated !== 'boolean') return false;

  if (obj.transaction_id !== undefined && obj.transaction_id !== null) {
    if (typeof obj.transaction_id !== 'string') return false;
  }

  if (obj.balance !== undefined && obj.balance !== null) {
    if (typeof obj.balance !== 'string') return false;
  }

  return true;
}

export function isHealthResponse(val: unknown): val is HealthResponse {
  if (!val || typeof val !== 'object') return false;
  const obj = val as Record<string, unknown>;
  return (
    typeof obj.status === 'string' &&
    typeof obj.service === 'string' &&
    typeof obj.simulated === 'boolean' &&
    typeof obj.currency === 'string'
  );
}

export function isDemoAccount(val: unknown): val is DemoAccount {
  if (!val || typeof val !== 'object') return false;
  const obj = val as Record<string, unknown>;
  return (
    typeof obj.user_id === 'string' &&
    obj.user_id.trim() !== '' &&
    typeof obj.display_name === 'string' &&
    typeof obj.simulated === 'boolean' &&
    typeof obj.currency === 'string' &&
    typeof obj.balance === 'string'
  );
}

/**
 * Distinguishes true attack categories from ordinary validation or unsupported operations.
 */
export function isAttackCategory(category: ThreatCategory): boolean {
  switch (category) {
    case 'PROMPT_INJECTION':
    case 'ROLEPLAY_JAILBREAK':
    case 'POLICY_OVERRIDE':
    case 'MEMO_INJECTION':
    case 'OBFUSCATION':
    case 'DATA_EXFILTRATION':
      return true;
    case 'VALIDATION_FAILURE':
    case 'UNSUPPORTED_OPERATION':
    case 'NONE':
    default:
      return false;
  }
}

export interface BlockHeadlineInfo {
  headline: 'THREAT NEUTRALIZED' | 'REQUEST BLOCKED';
  subheadline: string;
  isAttack: boolean;
}

/**
 * Human-readable wording for threat categories shown in the primary UI.
 * The raw enum value remains available in the details disclosure.
 */
export function getThreatCategoryLabel(category: ThreatCategory): string {
  switch (category) {
    case 'NONE':
      return 'No threat detected';
    case 'PROMPT_INJECTION':
      return 'Prompt injection attempt';
    case 'ROLEPLAY_JAILBREAK':
      return 'Roleplay jailbreak attempt';
    case 'POLICY_OVERRIDE':
      return 'Security policy override attempt';
    case 'MEMO_INJECTION':
      return 'Malicious content hidden in the payment memo';
    case 'OBFUSCATION':
      return 'Obfuscated or hidden content detected';
    case 'DATA_EXFILTRATION':
      return 'Attempt to access confidential account data';
    case 'VALIDATION_FAILURE':
      return 'The request could not be validated';
    case 'UNSUPPORTED_OPERATION':
      return 'This type of request is not supported';
    default:
      return category;
  }
}

/**
 * Returns accurate headline and subheadline wording based on endpoint and threat category.
 */
export function getBlockHeadlineInfo(
  category: ThreatCategory,
  endpoint: 'evaluate' | 'process',
  processContext?: { action_executed: boolean; simulated: boolean }
): BlockHeadlineInfo {
  const isAttack = isAttackCategory(category);
  const headline = isAttack ? 'THREAT NEUTRALIZED' : 'REQUEST BLOCKED';

  let subheadline: string;
  if (endpoint === 'evaluate') {
    subheadline = 'BLOCKED AT EVALUATION. NO ACTION WAS EXECUTED.';
  } else if (
    processContext &&
    processContext.action_executed === false &&
    processContext.simulated === true
  ) {
    subheadline = 'TRANSACTION BLOCKED. NO FUNDS MOVED (SIMULATED).';
  } else {
    subheadline = 'PROCESS REFUSED. NO ACTION EXECUTED.';
  }

  return { headline, subheadline, isAttack };
}

