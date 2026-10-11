import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  DemoAccount,
  EvaluationUiStatus,
  HealthResponse,
  ProcessResponse,
  ProcessUiStatus,
  RequestSnapshot,
  Verdict,
} from './types/firewall';
import {
  ApiHttpError,
  ApiSystemError,
  buildEvaluatePayload,
  checkHealth,
  createDemoAccount,
  evaluateRequest,
  fetchAccountSummary,
  processRequest,
} from './services/api';
import { HeaderStatus } from './components/HeaderStatus';
import { AICoreRadar, CoreState } from './components/AICoreRadar';
import { CommandConsole } from './components/CommandConsole';
import { VerdictPanel } from './components/VerdictPanel';
import { ProcessModal } from './components/ProcessModal';
import { ProcessResultPanel } from './components/ProcessResultPanel';
import { BootSequence } from './components/BootSequence';
import { AccountSetup, accountCreationErrorMessage } from './components/AccountSetup';
import { AccountSummaryCard } from './components/AccountSummaryCard';
import { WelcomeModal } from './components/WelcomeModal';
import { TourOverlay, TOUR_STEP_COUNT } from './components/TourOverlay';
import { SAMPLE_PROFILES } from './config/demoUsers';
import { DEMO_SCENARIOS } from './config/demoScenarios';

const SAMPLE_PROFILE_IDS = new Set(SAMPLE_PROFILES.map((profile) => profile.id));

type BootPhase = 'boot' | 'exiting' | 'done';
type AccountStatus = 'unknown' | 'restoring' | 'none' | 'missing' | 'error' | 'ready';

const ACCOUNT_STORAGE_KEY = 'bankism_account';
const ACCOUNT_LIST_KEY = 'bankism_accounts';
const MAX_REMEMBERED_ACCOUNTS = 10;

interface StoredAccountRef {
  user_id: string;
  display_name: string;
}

function readStoredAccountRef(): StoredAccountRef | null {
  try {
    const raw = sessionStorage.getItem(ACCOUNT_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<StoredAccountRef>;
    if (typeof parsed?.user_id === 'string' && parsed.user_id) {
      return {
        user_id: parsed.user_id,
        display_name: String(parsed.display_name ?? ''),
      };
    }
    return null;
  } catch {
    return null;
  }
}

function storeAccountRef(account: DemoAccount | null): void {
  try {
    if (account) {
      sessionStorage.setItem(
        ACCOUNT_STORAGE_KEY,
        JSON.stringify({
          user_id: account.user_id,
          display_name: account.display_name,
        })
      );
    } else {
      sessionStorage.removeItem(ACCOUNT_STORAGE_KEY);
    }
  } catch {
    // ignore storage failure
  }
}

function readStoredAccountList(): StoredAccountRef[] {
  try {
    const raw = sessionStorage.getItem(ACCOUNT_LIST_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (item): item is StoredAccountRef =>
        !!item &&
        typeof item === 'object' &&
        typeof (item as StoredAccountRef).user_id === 'string' &&
        !!(item as StoredAccountRef).user_id
    );
  } catch {
    return [];
  }
}

function addToStoredAccountList(ref: StoredAccountRef): StoredAccountRef[] {
  const existing = readStoredAccountList();
  const next = [
    ref,
    ...existing.filter((item) => item.user_id !== ref.user_id),
  ].slice(0, MAX_REMEMBERED_ACCOUNTS);
  try {
    sessionStorage.setItem(ACCOUNT_LIST_KEY, JSON.stringify(next));
  } catch {
    // ignore storage failure
  }
  return next;
}

export const App: React.FC = () => {
  // Boot sequence: 'boot' plays the intro, 'exiting' cross-fades into the
  // interface, 'done' renders the shell.
  const [bootPhase, setBootPhase] = useState<BootPhase>(() => {
    try {
      return sessionStorage.getItem('bankism_boot_completed') === 'true'
        ? 'done'
        : 'boot';
    } catch {
      return 'boot';
    }
  });
  const [healthData, setHealthData] = useState<HealthResponse | null>(null);
  const [healthRetryError, setHealthRetryError] = useState<string | null>(null);
  const [isRetryingHealth, setIsRetryingHealth] = useState(false);

  // Account state. The backend is the source of truth for balances; this
  // object is only ever populated from backend responses.
  const [account, setAccount] = useState<DemoAccount | null>(null);
  const [accountStatus, setAccountStatus] = useState<AccountStatus>('unknown');
  const [accountError, setAccountError] = useState<string | null>(null);
  const [isCreatingAccount, setIsCreatingAccount] = useState(false);
  // Accounts used this session (created or selected), for quick switching.
  // Seeded sample profiles are excluded — they have their own menu section.
  const [usedAccounts, setUsedAccounts] = useState<StoredAccountRef[]>(() =>
    readStoredAccountList().filter((ref) => !SAMPLE_PROFILE_IDS.has(ref.user_id))
  );

  // First-run onboarding: prompt once per session after an account is active.
  const [welcomeDone, setWelcomeDone] = useState<boolean>(() => {
    try {
      return sessionStorage.getItem('bankism_welcome_done') === 'true';
    } catch {
      return false;
    }
  });
  const [welcomeOpen, setWelcomeOpen] = useState(false);
  const [tourStep, setTourStep] = useState<number | null>(null);

  useEffect(() => {
    if (account && !welcomeDone) {
      setWelcomeOpen(true);
    } else {
      setWelcomeOpen(false);
    }
  }, [account, welcomeDone]);

  const dismissWelcome = useCallback(() => {
    setWelcomeOpen(false);
    setWelcomeDone(true);
    try {
      sessionStorage.setItem('bankism_welcome_done', 'true');
    } catch {
      // ignore storage failure
    }
  }, []);

  // Form inputs
  const [message, setMessage] = useState('send 500 to Priya');
  const [memo, setMemo] = useState('rent for October');

  // Request & verdict state
  const [snapshot, setSnapshot] = useState<RequestSnapshot | null>(null);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [evalUiStatus, setEvalUiStatus] = useState<EvaluationUiStatus>('IDLE');
  const [evalErrorMessage, setEvalErrorMessage] = useState<string | null>(null);

  // Process state
  const [processResult, setProcessResult] = useState<ProcessResponse | null>(null);
  const [processUiStatus, setProcessUiStatus] = useState<ProcessUiStatus>('IDLE');
  const [processErrorMessage, setProcessErrorMessage] = useState<string | null>(null);

  // Modal state
  const [modalState, setModalState] = useState<{
    isOpen: boolean;
    mode: 'normal' | 'execution_boundary';
  }>({
    isOpen: false,
    mode: 'normal',
  });

  // Evaluation lifecycle tracking
  const evalCounterRef = useRef(0);
  const activeEvalAbortControllerRef = useRef<AbortController | null>(null);

  // Background health probe once the shell is up (e.g. session restored).
  useEffect(() => {
    if (bootPhase === 'done' && !healthData) {
      checkHealth()
        .then((data) => setHealthData(data))
        .catch(() => {
          // Remains unavailable; the banner near the controls offers Retry.
        });
    }
  }, [bootPhase, healthData]);

  // Restore a previously created account (once, when leaving boot). Keyed
  // only on bootPhase: the promise updates below are idempotent, and no
  // cleanup cancellation is needed (state updates after unmount are no-ops).
  useEffect(() => {
    if (bootPhase === 'boot') return;
    if (account !== null || accountStatus !== 'unknown') return;

    const stored = readStoredAccountRef();
    if (!stored) {
      setAccountStatus('none');
      return;
    }

    setAccountStatus('restoring');
    fetchAccountSummary(stored.user_id)
      .then((data) => {
        setAccount(data); // balance comes from the backend response
        setAccountStatus('ready');
        setAccountError(null);
      })
      .catch((err: unknown) => {
        if (err instanceof ApiHttpError && err.status === 404) {
          storeAccountRef(null);
          setAccountStatus('missing');
        } else {
          setAccountStatus('error');
          setAccountError(
            err instanceof Error
              ? err.message
              : 'Could not restore the saved account'
          );
        }
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bootPhase]);

  // Switching accounts resets request state: verdicts belong to one account's
  // context. Server-side accounts are never deleted by this action; the used
  // list is remembered for the session so users can switch back at any time.
  const applyAccount = useCallback((next: DemoAccount | null) => {
    setAccount(next);
    storeAccountRef(next);
    if (next) {
      setUsedAccounts(
        addToStoredAccountList({
          user_id: next.user_id,
          display_name: next.display_name,
        }).filter((ref) => !SAMPLE_PROFILE_IDS.has(ref.user_id))
      );
    }
    setVerdict(null);
    setSnapshot(null);
    setEvalUiStatus('IDLE');
    setEvalErrorMessage(null);
    setProcessResult(null);
    setProcessUiStatus('IDLE');
    setProcessErrorMessage(null);
  }, []);

  const handleBootComplete = (health: HealthResponse | null) => {
    setHealthData(health);
    if (health) setHealthRetryError(null);
    setBootPhase('exiting');
  };

  const handleBootExited = () => {
    setBootPhase('done');
    try {
      sessionStorage.setItem('bankism_boot_completed', 'true');
    } catch {
      // ignore storage failure
    }
  };

  const handleReplayBoot = () => {
    try {
      sessionStorage.removeItem('bankism_boot_completed');
    } catch {
      // ignore
    }
    setBootPhase('boot');
  };

  const handleRetryHealth = useCallback(async () => {
    setIsRetryingHealth(true);
    setHealthRetryError(null);
    try {
      const data = await checkHealth();
      setHealthData(data);
      setHealthRetryError(null);
    } catch (err: unknown) {
      setHealthData(null);
      setHealthRetryError(
        err instanceof Error ? err.message : 'Security service unreachable'
      );
    } finally {
      setIsRetryingHealth(false);
    }
  }, []);

  // Account creation — always through the backend, never fabricated locally.
  const handleCreateAccount = useCallback(
    async (displayName: string, initialBalance: string) => {
      setIsCreatingAccount(true);
      setAccountError(null);
      try {
        const created = await createDemoAccount(displayName, initialBalance);
        applyAccount(created);
        setAccountStatus('ready');
      } catch (err: unknown) {
        setAccountError(accountCreationErrorMessage(err));
      } finally {
        setIsCreatingAccount(false);
      }
    },
    [applyAccount]
  );

  // Seeded sample profile (About menu): the balance still comes from the
  // backend account-summary response, never from client constants.
  const handleUseSampleProfile = useCallback(
    async (userId: string) => {
      setAccountError(null);
      try {
        const summary = await fetchAccountSummary(userId);
        applyAccount(summary);
        setAccountStatus('ready');
      } catch {
        // Keep the current account; service state is shown in the header.
      }
    },
    [applyAccount]
  );

  // Switch back to an account used earlier this session.
  const handleSelectAccount = useCallback(
    async (userId: string) => {
      setAccountError(null);
      try {
        const summary = await fetchAccountSummary(userId);
        applyAccount(summary);
        setAccountStatus('ready');
      } catch (err: unknown) {
        if (err instanceof ApiHttpError && err.status === 404) {
          // The demo store reset (server restart); drop it from the list.
          setUsedAccounts((prev) => prev.filter((ref) => ref.user_id !== userId));
        }
      }
    },
    [applyAccount]
  );

  // Log out: back to the setup screen. The account stays in the session's
  // used-account list (and server-side) so it can be logged back into.
  const handleLogout = useCallback(() => {
    applyAccount(null);
    setAccountStatus('none');
    setAccountError(null);
  }, [applyAccount]);

  const userId = account?.user_id ?? '';

  // Stale detection
  const isVerdictStale = Boolean(
    verdict &&
      snapshot &&
      (message.trim() !== snapshot.message ||
        memo.trim() !== snapshot.memo ||
        userId !== snapshot.userId)
  );

  // Refresh the displayed balance from the backend after a completed process.
  const refreshAccountSummary = useCallback(() => {
    if (!userId) return;
    fetchAccountSummary(userId)
      .then((data) => setAccount(data))
      .catch(() => {
        // Balance display keeps the last backend-confirmed value.
      });
  }, [userId]);

  // Handle evaluation submission
  const submitEvaluation = useCallback(
    async (requestMessage: string, requestMemo: string) => {
      if (!userId) return;

      // Abort any in-flight evaluation
      if (activeEvalAbortControllerRef.current) {
        activeEvalAbortControllerRef.current.abort();
      }

      const abortController = new AbortController();
      activeEvalAbortControllerRef.current = abortController;

      const currentEvalId = ++evalCounterRef.current;
      const trimmedMessage = requestMessage.trim();
      const trimmedMemo = requestMemo.trim();

      // Freeze snapshot at submission time
      const newSnapshot: RequestSnapshot = {
        message: trimmedMessage,
        memo: trimmedMemo,
        userId,
        timestamp: new Date().toISOString(),
        requestId: currentEvalId,
      };
      setSnapshot(newSnapshot);

      setEvalUiStatus('IN_FLIGHT');
      setEvalErrorMessage(null);

      const payload = buildEvaluatePayload(trimmedMessage, trimmedMemo, userId);

      try {
        const result = await evaluateRequest(payload, abortController.signal);

        // Ignore superseded evaluations
        if (evalCounterRef.current !== currentEvalId) {
          return;
        }

        setVerdict(result);
        setEvalUiStatus('SUCCESS');
      } catch (err: unknown) {
        if (evalCounterRef.current !== currentEvalId) {
          return;
        }

        if (err instanceof ApiHttpError) {
          setEvalUiStatus('REQUEST_REJECTED');
          setEvalErrorMessage(err.detail);
        } else if (err instanceof ApiSystemError) {
          setEvalUiStatus('SYSTEM_ERROR');
          setEvalErrorMessage(err.message);
        } else {
          setEvalUiStatus('SYSTEM_ERROR');
          setEvalErrorMessage(
            err instanceof Error ? err.message : 'Evaluation service error'
          );
        }
      } finally {
        if (evalCounterRef.current === currentEvalId) {
          activeEvalAbortControllerRef.current = null;
        }
      }
    },
    [userId]
  );

  const handleEvaluate = useCallback(() => {
    submitEvaluation(message, memo);
  }, [submitEvaluation, message, memo]);

  // Onboarding: one-click attack demo — loads a hidden-in-the-memo attack and
  // evaluates it so the interception moment plays immediately.
  const handleWelcomeDemo = useCallback(() => {
    const scenario = DEMO_SCENARIOS.find((s) => s.id === 'memo-injection');
    if (!scenario) return;
    dismissWelcome();
    setMessage(scenario.message);
    setMemo(scenario.memo || '');
    void submitEvaluation(scenario.message, scenario.memo || '');
  }, [dismissWelcome, submitEvaluation]);

  const handleStartTour = useCallback(() => {
    setWelcomeOpen(false);
    setTourStep(0);
  }, []);

  const handleEndTour = useCallback(() => {
    setTourStep(null);
    dismissWelcome();
  }, [dismissWelcome]);

  const handleReplayTour = useCallback(() => {
    setTourStep(0);
  }, []);

  const handleRestartTour = useCallback(() => {
    setTourStep(0);
  }, []);

  // Attack demo is also available on demand from the About menu.
  const handleMenuAttackDemo = useCallback(() => {
    handleWelcomeDemo();
  }, [handleWelcomeDemo]);

  // Handle process submission (state-changing; never aborted once sent)
  const handleConfirmProcess = useCallback(async () => {
    if (!userId) return;

    setModalState({ isOpen: false, mode: 'normal' });

    setProcessUiStatus('IN_FLIGHT');
    setProcessErrorMessage(null);

    const payload = buildEvaluatePayload(message.trim(), memo.trim(), userId);

    try {
      const result = await processRequest(payload);
      setProcessResult(result);
      setProcessUiStatus('SUCCESS');

      // Synchronize with a fresh server-side verdict if one was returned
      if (result.verdict) {
        setVerdict(result.verdict);
      }

      // Update the displayed balance only from backend responses.
      if (result.action_executed && typeof result.balance === 'string') {
        setAccount((prev) =>
          prev ? { ...prev, balance: result.balance as string } : prev
        );
      }
      refreshAccountSummary();
    } catch (err: unknown) {
      if (err instanceof ApiHttpError) {
        setProcessUiStatus('REQUEST_REJECTED');
        setProcessErrorMessage(err.detail);
      } else if (err instanceof ApiSystemError && err.kind === 'TIMEOUT') {
        setProcessUiStatus('EXECUTION_UNKNOWN');
        setProcessErrorMessage(
          'Process request timed out after 8 seconds. Simulated transfer status is unknown.'
        );
      } else if (err instanceof ApiSystemError && err.kind === 'NETWORK') {
        setProcessUiStatus('EXECUTION_UNKNOWN');
        setProcessErrorMessage(
          'Network connection interrupted during processing. Simulated transfer status is unknown.'
        );
      } else {
        setProcessUiStatus('EXECUTION_UNKNOWN');
        setProcessErrorMessage(
          err instanceof Error ? err.message : 'Unresolved communication failure'
        );
      }
    }
  }, [message, memo, userId, refreshAccountSummary]);

  // Central core visual state
  let coreState: CoreState = 'idle';
  if (evalUiStatus === 'IN_FLIGHT') {
    coreState = 'evaluating';
  } else if (processUiStatus === 'IN_FLIGHT') {
    coreState = 'processing';
  } else if (isVerdictStale) {
    coreState = 'stale';
  } else if (verdict?.decision === 'APPROVE') {
    coreState = 'approved';
  } else if (verdict?.decision === 'BLOCK') {
    coreState = 'threat_neutralized';
  }

  const shellProps = {
    coreState,
    healthData,
    isRetryingHealth,
    healthRetryError,
    account,
    accountStatus,
    accountError,
    isCreatingAccount,
    message,
    memo,
    verdict,
    snapshot,
    evalUiStatus,
    evalErrorMessage,
    processResult,
    processUiStatus,
    processErrorMessage,
    modalState,
    isVerdictStale,
    onMessageChange: setMessage,
    onMemoChange: setMemo,
    onEvaluate: handleEvaluate,
    onOpenProcessModal: () => setModalState({ isOpen: true, mode: 'normal' }),
    onOpenExecutionBoundaryModal: () =>
      setModalState({ isOpen: true, mode: 'execution_boundary' }),
    onRetryHealth: handleRetryHealth,
    onCreateAccount: handleCreateAccount,
    onSelectAccount: handleSelectAccount,
    onLogout: handleLogout,
    usedAccounts,
    onUseSampleProfile: handleUseSampleProfile,
    onReplayBoot: handleReplayBoot,
    onReplayTour: handleReplayTour,
    onAttackDemo: handleMenuAttackDemo,
    welcomeOpen,
    tourStep,
    onWelcomeTour: handleStartTour,
    onWelcomeDemo: handleWelcomeDemo,
    onWelcomeSkip: dismissWelcome,
    onTourNext: () => setTourStep((s) => Math.min((s ?? 0) + 1, TOUR_STEP_COUNT - 1)),
    onTourBack: () => setTourStep((s) => Math.max((s ?? 0) - 1, 0)),
    onTourRestart: handleRestartTour,
    onTourEnd: handleEndTour,
    onConfirmProcess: handleConfirmProcess,
    onCloseModal: () => setModalState({ isOpen: false, mode: 'normal' }),
    onClearProcess: () => {
      setProcessResult(null);
      setProcessUiStatus('IDLE');
    },
  };

  if (bootPhase !== 'done') {
    return (
      <>
        {/* Mount the shell beneath the boot overlay during the exit
            transition so the core cross-fades into place. The content area
            stays empty until 'done' to avoid a layout flip during the fade. */}
        {bootPhase === 'exiting' && (
          <div className="main-enter">
            <AppShell {...shellProps} />
          </div>
        )}
        <BootSequence
          onComplete={handleBootComplete}
          exiting={bootPhase === 'exiting'}
          onExited={handleBootExited}
        />
      </>
    );
  }

  return <AppShell {...shellProps} />;
};

interface AppShellProps {
  coreState: CoreState;
  healthData: HealthResponse | null;
  isRetryingHealth: boolean;
  healthRetryError: string | null;
  account: DemoAccount | null;
  accountStatus: AccountStatus;
  accountError: string | null;
  isCreatingAccount: boolean;
  message: string;
  memo: string;
  verdict: Verdict | null;
  snapshot: RequestSnapshot | null;
  evalUiStatus: EvaluationUiStatus;
  evalErrorMessage: string | null;
  processResult: ProcessResponse | null;
  processUiStatus: ProcessUiStatus;
  processErrorMessage: string | null;
  modalState: { isOpen: boolean; mode: 'normal' | 'execution_boundary' };
  isVerdictStale: boolean;
  onMessageChange: (v: string) => void;
  onMemoChange: (v: string) => void;
  onEvaluate: () => void;
  onOpenProcessModal: () => void;
  onOpenExecutionBoundaryModal: () => void;
  onRetryHealth: () => void;
  onCreateAccount: (displayName: string, initialBalance: string) => Promise<void>;
  onSelectAccount: (userId: string) => void;
  onLogout: () => void;
  usedAccounts: StoredAccountRef[];
  onUseSampleProfile: (userId: string) => void;
  onReplayBoot: () => void;
  onReplayTour: () => void;
  onAttackDemo: () => void;
  welcomeOpen: boolean;
  tourStep: number | null;
  onWelcomeTour: () => void;
  onWelcomeDemo: () => void;
  onWelcomeSkip: () => void;
  onTourNext: () => void;
  onTourBack: () => void;
  onTourRestart: () => void;
  onTourEnd: () => void;
  onConfirmProcess: () => void;
  onCloseModal: () => void;
  onClearProcess: () => void;
}

const AppShell: React.FC<AppShellProps> = ({
  coreState,
  healthData,
  isRetryingHealth,
  healthRetryError,
  account,
  accountStatus,
  accountError,
  isCreatingAccount,
  message,
  memo,
  verdict,
  snapshot,
  evalUiStatus,
  evalErrorMessage,
  processResult,
  processUiStatus,
  processErrorMessage,
  modalState,
  isVerdictStale,
  onMessageChange,
  onMemoChange,
  onEvaluate,
  onOpenProcessModal,
  onOpenExecutionBoundaryModal,
  onRetryHealth,
  onCreateAccount,
  onSelectAccount,
  onLogout,
  usedAccounts,
  onUseSampleProfile,
  onReplayBoot,
  onReplayTour,
  onAttackDemo,
  welcomeOpen,
  tourStep,
  onWelcomeTour,
  onWelcomeDemo,
  onWelcomeSkip,
  onTourNext,
  onTourBack,
  onTourRestart,
  onTourEnd,
  onConfirmProcess,
  onCloseModal,
  onClearProcess,
}) => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <HeaderStatus
        health={healthData}
        onReplayBoot={onReplayBoot}
        onUseSampleProfile={onUseSampleProfile}
        onSelectAccount={onSelectAccount}
        onLogout={onLogout}
        onReplayTour={onReplayTour}
        onAttackDemo={onAttackDemo}
        usedAccounts={usedAccounts}
        activeAccountId={account?.user_id ?? null}
      />

      <main className="app-main">
        {/* Honest availability notice near the request controls */}
        {!healthData && (
          <div className="availability-banner" role="status">
            <span className="banner-dot" aria-hidden="true" />
            <span className="banner-text">
              Security service unavailable. Requests cannot be evaluated right now.
              {healthRetryError && (
                <span
                  className="font-mono"
                  style={{ fontSize: 11, display: 'block', opacity: 0.8 }}
                >
                  {healthRetryError}
                </span>
              )}
            </span>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={onRetryHealth}
              disabled={isRetryingHealth}
            >
              {isRetryingHealth ? 'Checking…' : 'Retry'}
            </button>
          </div>
        )}

        {/* Central AI core — the consistent visual anchor */}
        <section className="core-hero" id="tour-core" aria-label="Bankism security core">
          <AICoreRadar
            state={coreState}
            decision={verdict?.decision}
            riskLevel={verdict?.risk_level}
            threatCategory={verdict?.threat_category}
            isStale={isVerdictStale}
            size={240}
          />
          {account && <AccountSummaryCard account={account} />}
        </section>

        {account ? (
          <>
            {/* Request controls + current security result */}
            <div className="workspace-grid">
              <div id="tour-console">
                <CommandConsole
                  message={message}
                  memo={memo}
                  onMessageChange={onMessageChange}
                  onMemoChange={onMemoChange}
                  onEvaluate={onEvaluate}
                  onOpenProcessModal={onOpenProcessModal}
                  onOpenExecutionBoundaryModal={onOpenExecutionBoundaryModal}
                  isEvaluating={evalUiStatus === 'IN_FLIGHT'}
                  isProcessing={processUiStatus === 'IN_FLIGHT'}
                  latestDecision={verdict?.decision || null}
                  isVerdictStale={isVerdictStale}
                />
              </div>

              <div id="tour-result">
                <VerdictPanel
                  verdict={verdict}
                  uiStatus={evalUiStatus}
                  errorMessage={evalErrorMessage}
                  isStale={isVerdictStale}
                  onRetry={onEvaluate}
                  rawResponseJson={verdict}
                  snapshot={snapshot}
                />
              </div>
            </div>

            {/* Appears only after a process request has been made */}
            <ProcessResultPanel
              processResult={processResult}
              uiStatus={processUiStatus}
              errorMessage={processErrorMessage}
              onClear={onClearProcess}
            />
          </>
        ) : (
          <div className="setup-stage">
            {accountStatus === 'restoring' ? (
              <p className="text-muted" style={{ fontSize: 13, textAlign: 'center' }}>
                Restoring your simulated account…
              </p>
            ) : (
              <AccountSetup
                onCreate={onCreateAccount}
                isCreating={isCreatingAccount}
                errorMessage={accountError}
                missingAccountNotice={accountStatus === 'missing'}
                savedAccounts={usedAccounts}
                onSelectAccount={onSelectAccount}
              />
            )}
          </div>
        )}
      </main>

      <ProcessModal
        isOpen={modalState.isOpen}
        mode={modalState.mode}
        verdict={verdict}
        userId={account?.user_id || ''}
        onConfirm={onConfirmProcess}
        onCancel={onCloseModal}
        isProcessing={processUiStatus === 'IN_FLIGHT'}
      />

      {welcomeOpen && (
        <WelcomeModal
          onTour={onWelcomeTour}
          onDemo={onWelcomeDemo}
          onSkip={onWelcomeSkip}
        />
      )}

      {tourStep !== null && (
        <TourOverlay
          step={tourStep}
          onNext={onTourNext}
          onBack={onTourBack}
          onRestart={onTourRestart}
          onEnd={onTourEnd}
        />
      )}

      <footer
        style={{
          borderTop: '1px solid rgba(0, 242, 254, 0.07)',
          padding: '16px 24px',
          textAlign: 'center',
          marginTop: 'auto',
        }}
      >
        <div className="text-muted" style={{ fontSize: 12, lineHeight: 1.6 }}>
          BANKISM — intelligent banking security. All accounts and transactions are
          simulated. Account IDs are demo selectors, not authentication.
        </div>
      </footer>
    </div>
  );
};
