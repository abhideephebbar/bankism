import React from 'react';

interface WelcomeModalProps {
  onTour: () => void;
  onDemo: () => void;
  onSkip: () => void;
}

/**
 * First-run prompt shown once per session after an account becomes active.
 * Offers a guided tour, a one-click attack demo, or skipping.
 */
export const WelcomeModal: React.FC<WelcomeModalProps> = ({ onTour, onDemo, onSkip }) => {
  return (
    <div className="modal-backdrop" role="presentation">
      <div
        className="modal-dialog welcome-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="welcome-title"
        style={{ maxWidth: 460, textAlign: 'center' }}
      >
        <h2
          id="welcome-title"
          style={{
            fontSize: 18,
            fontWeight: 800,
            letterSpacing: '0.5px',
            color: '#ffffff',
            marginBottom: 8,
          }}
        >
          Welcome to Bankism
        </h2>
        <p className="text-secondary" style={{ fontSize: 13, lineHeight: 1.6, marginBottom: 20 }}>
          Every request is checked before any action. Take a quick tour, or watch
          Bankism neutralize a hidden attack in seconds.
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <button type="button" className="btn btn-primary" onClick={onTour}>
            Take the tour
          </button>
          <button type="button" className="btn btn-execute" onClick={onDemo}>
            See it block an attack
          </button>
          <button type="button" className="btn btn-secondary" onClick={onSkip}>
            Skip for now
          </button>
        </div>

        <p className="text-muted" style={{ fontSize: 11, marginTop: 16 }}>
          You can replay the tour anytime from the About menu.
        </p>
      </div>
    </div>
  );
};
