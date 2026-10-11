import React from 'react';
import { HealthResponse } from '../types/firewall';
import { AboutMenu } from './AboutMenu';

interface AccountRef {
  user_id: string;
  display_name: string;
}

interface HeaderStatusProps {
  health: HealthResponse | null;
  onReplayBoot?: () => void;
  onUseSampleProfile?: (userId: string) => void;
  onSelectAccount?: (userId: string) => void;
  onNewAccount?: () => void;
  onReplayTour?: () => void;
  usedAccounts?: AccountRef[];
  activeAccountId?: string | null;
}

export const HeaderStatus: React.FC<HeaderStatusProps> = ({
  health,
  onReplayBoot,
  onUseSampleProfile,
  onSelectAccount,
  onNewAccount,
  onReplayTour,
  usedAccounts = [],
  activeAccountId = null,
}) => {
  const showMenu = Boolean(
    onReplayBoot && onUseSampleProfile && onSelectAccount && onNewAccount
  );

  return (
    <header
      style={{
        borderBottom: '1px solid rgba(0, 242, 254, 0.08)',
        background: 'rgba(4, 6, 10, 0.7)',
        backdropFilter: 'blur(12px)',
        padding: '14px 24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 12,
        position: 'sticky',
        top: 0,
        zIndex: 50,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <span
          aria-hidden="true"
          style={{
            width: 10,
            height: 10,
            borderRadius: '50%',
            background: 'var(--color-cyan)',
            boxShadow: '0 0 12px var(--color-cyan)',
            flexShrink: 0,
          }}
        />
        <div>
          <h1
            style={{
              fontSize: 17,
              fontWeight: 800,
              letterSpacing: '5px',
              textTransform: 'uppercase',
              lineHeight: 1.2,
              color: '#ffffff',
            }}
          >
            BANKISM
          </h1>
          <span
            style={{
              fontSize: 11,
              color: 'var(--text-secondary)',
              letterSpacing: '0.3px',
              display: 'block',
              marginTop: 1,
            }}
          >
            Every request. Checked before action.
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        {!health && (
          <span
            role="status"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 7,
              fontSize: 12,
              color: 'var(--color-amber)',
            }}
          >
            <span
              aria-hidden="true"
              style={{
                width: 7,
                height: 7,
                borderRadius: '50%',
                background: 'var(--color-amber)',
              }}
            />
            Service unavailable
          </span>
        )}

        {showMenu && (
          <AboutMenu
            onReplayBoot={onReplayBoot as () => void}
            onUseSampleProfile={onUseSampleProfile as (id: string) => void}
            onSelectAccount={onSelectAccount as (id: string) => void}
            onNewAccount={onNewAccount as () => void}
            onReplayTour={onReplayTour}
            usedAccounts={usedAccounts}
            activeAccountId={activeAccountId}
          />
        )}
      </div>
    </header>
  );
};
