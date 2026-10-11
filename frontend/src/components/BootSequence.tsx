import React, { useEffect, useRef, useState } from 'react';
import { checkHealth } from '../services/api';
import { HealthResponse } from '../types/firewall';
import { AICoreRadar } from './AICoreRadar';

interface BootSequenceProps {
  /** Called when the intro finishes. `null` health means the service is unavailable. */
  onComplete: (health: HealthResponse | null) => void;
  /** When true, the intro plays its exit transition and then calls onExited. */
  exiting?: boolean;
  onExited?: () => void;
}

type BootStage = 'emerge' | 'ready' | 'title';

export const BootSequence: React.FC<BootSequenceProps> = ({
  onComplete,
  exiting = false,
  onExited,
}) => {
  const [stage, setStage] = useState<BootStage>('emerge');
  const [healthResolved, setHealthResolved] = useState(false);
  const healthRef = useRef<HealthResponse | null>(null);

  const prefersReducedMotion =
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // Probe the backend in the background for the whole sequence.
  useEffect(() => {
    const abortController = new AbortController();
    checkHealth(abortController.signal)
      .then((data) => {
        healthRef.current = data;
        setHealthResolved(true);
      })
      .catch(() => {
        healthRef.current = null;
        setHealthResolved(true);
      });
    return () => abortController.abort();
  }, []);

  // Stage timeline (~3.4s): core emerges, systems settle, title reveals.
  useEffect(() => {
    if (prefersReducedMotion) {
      // Keep the intro short but never claim readiness before we know the
      // health outcome; if the probe is still in flight, wait for it.
      const timer = setTimeout(() => {
        if (healthResolved) {
          setStage('title');
        }
      }, 400);
      return () => clearTimeout(timer);
    }

    const t1 = setTimeout(() => setStage('ready'), 1700);
    const t2 = setTimeout(() => setStage('title'), 2500);
    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
    };
  }, [prefersReducedMotion, healthResolved]);

  // Complete once the title has been revealed (and, in reduced-motion mode,
  // the health probe has settled).
  useEffect(() => {
    if (stage !== 'title') return;
    if (prefersReducedMotion && !healthResolved) return;

    if (prefersReducedMotion) {
      onComplete(healthRef.current);
      return;
    }
    const timer = setTimeout(() => onComplete(healthRef.current), 900);
    return () => clearTimeout(timer);
  }, [stage, healthResolved, prefersReducedMotion, onComplete]);

  // Exit transition: fade the whole overlay, then unmount.
  useEffect(() => {
    if (!exiting) return;
    const timer = setTimeout(() => {
      if (onExited) onExited();
    }, 640);
    return () => clearTimeout(timer);
  }, [exiting, onExited]);

  // Escape skips the intro; the health outcome is still honored.
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onComplete(healthRef.current);
      }
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [onComplete]);

  const handleSkip = () => {
    onComplete(healthRef.current);
  };

  const statusText =
    stage === 'emerge'
      ? 'INITIALIZING'
      : stage === 'ready'
      ? healthResolved && healthRef.current
        ? 'SYSTEMS READY'
        : 'INITIALIZING'
      : '';

  return (
    <div
      className={`boot-container ${exiting ? 'boot-exit' : ''}`}
      aria-live="polite"
      aria-label="Bankism startup sequence"
    >
      <button
        type="button"
        className="btn btn-secondary boot-skip"
        onClick={handleSkip}
      >
        Skip intro
      </button>

      <div className="boot-core-wrap">
        <span className="boot-ring" aria-hidden="true" />
        <span className="boot-ring ring-2" aria-hidden="true" />
        <AICoreRadar
          state={stage === 'emerge' ? 'idle' : 'evaluating'}
          size={prefersReducedMotion ? 200 : 240}
        />
      </div>

      <div className="boot-message">
        {stage === 'title' ? (
          <div className="boot-title">BANKISM</div>
        ) : (
          <div className="boot-status-text" key={statusText}>
            {statusText}
          </div>
        )}
      </div>
    </div>
  );
};
