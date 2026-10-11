import React, { useEffect } from 'react';

interface TourStep {
  targetId: string;
  title: string;
  body: string;
}

const STEPS: TourStep[] = [
  {
    targetId: 'tour-core',
    title: 'The security core',
    body: 'This core is the heart of Bankism. It stays calm while waiting, scans while evaluating, and flashes the interception sequence when it blocks a threat.',
  },
  {
    targetId: 'tour-console',
    title: 'Make a request',
    body: 'Describe a transfer or balance check in plain English — for example "send 500 to Priya". The memo is optional, and it is always treated as data, never as a command.',
  },
  {
    targetId: 'tour-result',
    title: 'The verdict',
    body: 'Every result is APPROVED or BLOCKED, with the reason in plain language. Approval from evaluation never moves money — only an explicit, confirmed Process does.',
  },
  {
    targetId: 'tour-about',
    title: 'Everything else',
    body: 'Switch accounts, try sample profiles, replay this tour, or dig into Raw JSON — all from the About menu. Try an example chip to load a request instantly.',
  },
];

interface TourOverlayProps {
  step: number;
  onNext: () => void;
  onBack: () => void;
  onRestart: () => void;
  onEnd: () => void;
}

/**
 * Lightweight spotlight tour: highlights one area at a time with a fixed
 * caption card. Spotlight is a CSS class toggled on the target element.
 */
export const TourOverlay: React.FC<TourOverlayProps> = ({ step, onNext, onBack, onRestart, onEnd }) => {
  const current = STEPS[Math.min(step, STEPS.length - 1)];
  const isFirst = step === 0;
  const isLast = step === STEPS.length - 1;

  useEffect(() => {
    const target = document.getElementById(current.targetId);
    target?.classList.add('tour-spotlight');
    return () => target?.classList.remove('tour-spotlight');
  }, [current.targetId]);

  return (
    <>
      <div className="tour-scrim" aria-hidden="true" />
      <div
        className="tour-card"
        role="dialog"
        aria-label={`Tour step ${step + 1} of ${STEPS.length}: ${current.title}`}
      >
        <div className="tour-progress" aria-hidden="true">
          {STEPS.map((_, i) => (
            <span key={i} className={`tour-dot ${i === step ? 'active' : ''}`} />
          ))}
        </div>
        <h3 className="tour-title">{current.title}</h3>
        <p className="tour-body">{current.body}</p>
        <div className="tour-actions">
          {!isFirst && (
            <button type="button" className="btn btn-secondary" onClick={onBack} style={{ fontSize: 12 }}>
              Back
            </button>
          )}
          <button type="button" className="btn btn-secondary" onClick={onRestart} style={{ fontSize: 12 }}>
            Restart
          </button>
          <button type="button" className="btn btn-secondary" onClick={onEnd} style={{ fontSize: 12 }}>
            End tour
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={isLast ? onEnd : onNext}
            style={{ fontSize: 12 }}
          >
            {isLast ? 'Finish' : 'Next'}
          </button>
        </div>
      </div>
    </>
  );
};

export const TOUR_STEP_COUNT = STEPS.length;
