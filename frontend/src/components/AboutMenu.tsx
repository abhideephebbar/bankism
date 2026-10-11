import React, { useEffect, useRef, useState } from 'react';
import { SAMPLE_PROFILES } from '../config/demoUsers';

interface AccountRef {
  user_id: string;
  display_name: string;
}

interface AboutMenuProps {
  onReplayBoot: () => void;
  onUseSampleProfile: (userId: string) => void;
  onSelectAccount: (userId: string) => void;
  onNewAccount: () => void;
  usedAccounts: AccountRef[];
  activeAccountId: string | null;
}

/**
 * Small header menu holding secondary actions: switching between accounts
 * used this session, seeded sample profiles, creating a new account, and
 * replaying the intro. Keeps the main interface clean while leaving these
 * capabilities discoverable.
 */
export const AboutMenu: React.FC<AboutMenuProps> = ({
  onReplayBoot,
  onUseSampleProfile,
  onSelectAccount,
  onNewAccount,
  usedAccounts,
  activeAccountId,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!isOpen) return;
    const handlePointerDown = (e: PointerEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setIsOpen(false);
    };
    document.addEventListener('pointerdown', handlePointerDown);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('pointerdown', handlePointerDown);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen]);

  const switchableAccounts = usedAccounts.filter(
    (ref) => ref.user_id !== activeAccountId
  );

  return (
    <div ref={containerRef} style={{ position: 'relative' }}>
      <button
        type="button"
        className="btn btn-secondary"
        onClick={() => setIsOpen(!isOpen)}
        aria-expanded={isOpen}
        aria-haspopup="menu"
        style={{ fontSize: 12, padding: '5px 12px' }}
      >
        About
      </button>

      {isOpen && (
        <div className="about-menu" role="menu" aria-label="About and settings">
          <button
            type="button"
            role="menuitem"
            className="about-menu-item"
            onClick={() => {
              setIsOpen(false);
              onNewAccount();
            }}
          >
            Create a new account
          </button>

          {switchableAccounts.length > 0 && (
            <>
              <div className="about-menu-heading">Your accounts</div>
              {switchableAccounts.map((ref) => (
                <button
                  key={ref.user_id}
                  type="button"
                  role="menuitem"
                  className="about-menu-item"
                  onClick={() => {
                    setIsOpen(false);
                    onSelectAccount(ref.user_id);
                  }}
                >
                  {ref.display_name || ref.user_id}
                  <span className="about-menu-item-meta">{ref.user_id}</span>
                </button>
              ))}
            </>
          )}

          <div className="about-menu-heading">Sample profiles</div>
          {SAMPLE_PROFILES.filter((p) => p.id !== activeAccountId).map((profile) => (
            <button
              key={profile.id}
              type="button"
              role="menuitem"
              className="about-menu-item"
              onClick={() => {
                setIsOpen(false);
                onUseSampleProfile(profile.id);
              }}
            >
              {profile.displayName}
              <span className="about-menu-item-meta">{profile.seededBalance} INR</span>
            </button>
          ))}

          <button
            type="button"
            role="menuitem"
            className="about-menu-item"
            onClick={() => {
              setIsOpen(false);
              onReplayBoot();
            }}
          >
            Replay intro
          </button>

          <p className="about-menu-note">
            Demo accounts live only in server memory and disappear on restart.
            Account IDs are demo selectors, not authentication.
          </p>
        </div>
      )}
    </div>
  );
};
