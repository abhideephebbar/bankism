import React from 'react';
import { DemoAccount } from '../types/firewall';

interface AccountSummaryCardProps {
  account: DemoAccount;
}

/**
 * Compact account summary shown near the core. The balance is displayed
 * exactly as returned by the backend — never computed in the frontend.
 */
export const AccountSummaryCard: React.FC<AccountSummaryCardProps> = ({ account }) => {
  return (
    <div
      className="account-summary"
      role="status"
      aria-label={`Simulated account ${account.display_name}, balance ${account.balance} ${account.currency}`}
    >
      <div className="account-summary-name">{account.display_name}</div>
      <div className="account-summary-balance">
        <span className="font-mono">{account.balance}</span>
        <span className="account-summary-currency">{account.currency}</span>
      </div>
      <div className="account-summary-hint">Simulated balance</div>
    </div>
  );
};
