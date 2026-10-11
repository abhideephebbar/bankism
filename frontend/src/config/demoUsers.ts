/**
 * DEMO IDENTITY SELECTORS, NOT AUTHENTICATION.
 *
 * In a real-world banking system, sender identity must originate from an
 * authenticated session, cryptographic token, or mTLS identity.
 * In this simulated Bankism demonstration, these IDs are seeded static
 * identity selectors read directly from backend/app/banking.py.
 *
 * The backend does not expose a user-listing endpoint.
 */

export interface DemoPayee {
  id: string;
  name: string;
  account: string;
}

export interface DemoUser {
  id: string;
  displayName: string;
  seededBalance: string;
  payees: DemoPayee[];
}

export const DEMO_USERS: Record<string, DemoUser> = {
  alice: {
    id: 'alice',
    displayName: 'Alice',
    seededBalance: '25000.00',
    payees: [
      { id: 'priya', name: 'Priya', account: 'AC-PRIYA-001' },
      { id: 'rahul', name: 'Rahul', account: 'AC-RAHUL-002' },
      { id: 'meera', name: 'Meera', account: 'AC-MEERA-003' },
      { id: 'arjun', name: 'Arjun', account: 'AC-ARJUN-004' },
    ],
  },
  bob: {
    id: 'bob',
    displayName: 'Bob',
    seededBalance: '12000.00',
    payees: [
      { id: 'priya', name: 'Priya', account: 'AC-PRIYA-001' },
      { id: 'kiran', name: 'Kiran', account: 'AC-KIRAN-005' },
      { id: 'deepa', name: 'Deepa', account: 'AC-DEEPA-006' },
    ],
  },
  carol: {
    id: 'carol',
    displayName: 'Carol',
    seededBalance: '8000.00',
    payees: [
      { id: 'rahul', name: 'Rahul', account: 'AC-RAHUL-002' },
      { id: 'sana', name: 'Sana', account: 'AC-SANA-007' },
      { id: 'vikram', name: 'Vikram', account: 'AC-VIKRAM-008' },
    ],
  },
};

export const DEFAULT_DEMO_USER_ID = 'alice';

/**
 * Seeded sample profiles, tucked away in the About menu as optional
 * starting points. They are demo identity selectors, NOT authentication,
 * and the backend never exposes a user-listing endpoint.
 */
export const SAMPLE_PROFILES: DemoUser[] = [
  DEMO_USERS.alice,
  DEMO_USERS.bob,
  DEMO_USERS.carol,
];

