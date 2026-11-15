import type { LoginSummary } from '$lib/types/generated/LoginSummary';

/**
 * Estados de la máquina de estados finitos (FSM) del agente y la bóveda.
 */
export type VaultStatus =
  | { state: 'disconnected' }
  | { state: 'needs_setup' }
  | { state: 'logged_out' }
  | { state: 'locked' }
  | { state: 'unlocking' }
  | { state: 'unlocked'; logins: LoginSummary[] }
  | { state: 'syncing'; logins: LoginSummary[] }
  | { state: 'error'; message: string };

export type VaultStateName = VaultStatus['state'];
