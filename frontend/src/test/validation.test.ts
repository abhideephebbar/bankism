import { describe, it, expect } from 'vitest';
import {
  getBlockHeadlineInfo,
  isAttackCategory,
  isDecision,
  isHealthResponse,
  isIntent,
  isProcessResponse,
  isRiskLevel,
  isThreatCategory,
  isVerdict,
} from '../utils/validation';

describe('Validation Type Guards & Helpers', () => {
  it('validates Decision enums strictly', () => {
    expect(isDecision('APPROVE')).toBe(true);
    expect(isDecision('BLOCK')).toBe(true);
    expect(isDecision('ALLOW')).toBe(false);
    expect(isDecision(null)).toBe(false);
    expect(isDecision(123)).toBe(false);
  });

  it('validates RiskLevel enums strictly', () => {
    expect(isRiskLevel('LOW')).toBe(true);
    expect(isRiskLevel('MEDIUM')).toBe(true);
    expect(isRiskLevel('HIGH')).toBe(true);
    expect(isRiskLevel('CRITICAL')).toBe(true);
    expect(isRiskLevel('MODERATE')).toBe(false);
  });

  it('validates all ThreatCategory enum values from backend/app/schemas.py', () => {
    const valid = [
      'NONE',
      'PROMPT_INJECTION',
      'ROLEPLAY_JAILBREAK',
      'POLICY_OVERRIDE',
      'MEMO_INJECTION',
      'OBFUSCATION',
      'DATA_EXFILTRATION',
      'VALIDATION_FAILURE',
      'UNSUPPORTED_OPERATION',
    ];
    for (const cat of valid) {
      expect(isThreatCategory(cat)).toBe(true);
    }
    expect(isThreatCategory('SQL_INJECTION')).toBe(false);
  });

  it('validates Intent enums strictly', () => {
    expect(isIntent('NONE')).toBe(true);
    expect(isIntent('BALANCE_INQUIRY')).toBe(true);
    expect(isIntent('TRANSFER')).toBe(true);
    expect(isIntent('UNSUPPORTED')).toBe(true);
    expect(isIntent('PAYMENT')).toBe(false);
  });

  it('validates a complete valid Verdict', () => {
    const validVerdict = {
      request_id: 'req-01',
      decision: 'APPROVE',
      risk_level: 'LOW',
      threat_category: 'NONE',
      rationale: 'Valid transaction request.',
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
    expect(isVerdict(validVerdict)).toBe(true);
  });

  it('rejects a malformed Verdict missing required fields or invalid enums', () => {
    expect(isVerdict(null)).toBe(false);
    expect(isVerdict({})).toBe(false);
    // Missing request_id
    expect(
      isVerdict({
        decision: 'APPROVE',
        risk_level: 'LOW',
        threat_category: 'NONE',
        rationale: 'ok',
        intent: 'TRANSFER',
        validation_errors: [],
        signals: [],
      })
    ).toBe(false);
    // Invalid decision
    expect(
      isVerdict({
        request_id: 'req-02',
        decision: 'PASS',
        risk_level: 'LOW',
        threat_category: 'NONE',
        rationale: 'ok',
        intent: 'TRANSFER',
        validation_errors: [],
        signals: [],
      })
    ).toBe(false);
    // Non-array validation_errors
    expect(
      isVerdict({
        request_id: 'req-03',
        decision: 'BLOCK',
        risk_level: 'HIGH',
        threat_category: 'PROMPT_INJECTION',
        rationale: 'attack',
        intent: 'NONE',
        validation_errors: 'not an array',
        signals: [],
      })
    ).toBe(false);
  });

  it('validates a complete ProcessResponse and rejects malformed ones', () => {
    const validProcess = {
      verdict: {
        request_id: 'req-04',
        decision: 'APPROVE',
        risk_level: 'LOW',
        threat_category: 'NONE',
        rationale: 'transfer approved',
        intent: 'TRANSFER',
        validation_errors: [],
        signals: [],
      },
      action_executed: true,
      simulated: true,
      transaction_id: 'TXN-000001',
      balance: '24500.00',
    };
    expect(isProcessResponse(validProcess)).toBe(true);

    // Missing action_executed
    const missingAction = { ...validProcess, action_executed: undefined };
    expect(isProcessResponse(missingAction)).toBe(false);

    // Invalid nested verdict
    const invalidVerdict = { ...validProcess, verdict: { invalid: true } };
    expect(isProcessResponse(invalidVerdict)).toBe(false);
  });

  it('validates HealthResponse correctly', () => {
    expect(
      isHealthResponse({
        status: 'ok',
        service: 'bankism-firewall',
        simulated: true,
        currency: 'INR',
      })
    ).toBe(true);
    expect(isHealthResponse({ status: 'ok' })).toBe(false);
  });

  it('distinguishes attack categories from validation failures', () => {
    expect(isAttackCategory('PROMPT_INJECTION')).toBe(true);
    expect(isAttackCategory('ROLEPLAY_JAILBREAK')).toBe(true);
    expect(isAttackCategory('POLICY_OVERRIDE')).toBe(true);
    expect(isAttackCategory('MEMO_INJECTION')).toBe(true);
    expect(isAttackCategory('OBFUSCATION')).toBe(true);
    expect(isAttackCategory('DATA_EXFILTRATION')).toBe(true);

    expect(isAttackCategory('VALIDATION_FAILURE')).toBe(false);
    expect(isAttackCategory('UNSUPPORTED_OPERATION')).toBe(false);
    expect(isAttackCategory('NONE')).toBe(false);
  });

  it('generates accurate headlines based on category and endpoint', () => {
    // Attack category evaluated
    const attackEval = getBlockHeadlineInfo('PROMPT_INJECTION', 'evaluate');
    expect(attackEval.headline).toBe('THREAT NEUTRALIZED');
    expect(attackEval.subheadline).toBe(
      'BLOCKED AT EVALUATION. NO ACTION WAS EXECUTED.'
    );
    expect(attackEval.isAttack).toBe(true);

    // Validation failure evaluated
    const valEval = getBlockHeadlineInfo('VALIDATION_FAILURE', 'evaluate');
    expect(valEval.headline).toBe('REQUEST BLOCKED');
    expect(valEval.subheadline).toBe(
      'BLOCKED AT EVALUATION. NO ACTION WAS EXECUTED.'
    );
    expect(valEval.isAttack).toBe(false);

    // Attack blocked during process execution
    const attackProc = getBlockHeadlineInfo('POLICY_OVERRIDE', 'process', {
      action_executed: false,
      simulated: true,
    });
    expect(attackProc.headline).toBe('THREAT NEUTRALIZED');
    expect(attackProc.subheadline).toBe(
      'TRANSACTION BLOCKED. NO FUNDS MOVED (SIMULATED).'
    );
  });
});

