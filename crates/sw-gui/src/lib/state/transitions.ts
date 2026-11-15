import type { AgentStatus } from '$lib/types/generated/AgentStatus';
import type { LoginSummary } from '$lib/types/generated/LoginSummary';
import type { VaultStateName, VaultStatus } from './types';

/**
 * Tabla documentada de transiciones válidas entre estados de la FSM.
 *
 * Restricciones clave:
 * - No se puede sincronizar (`syncing`) desde `disconnected`, `needs_setup`, `logged_out` ni `locked`.
 * - No se puede iniciar `unlocking` ni `syncing` en paralelo (self-transition prohibida).
 * - Desde `unlocked` no se retrocede a `needs_setup` ni `unlocking` directamente.
 * - Cualquier estado puede derivar en `disconnected` (caída de socket IPC) o `error` (fallo de operación).
 */
export const TRANSITIONS: Readonly<Record<VaultStateName, readonly VaultStateName[]>> = {
  disconnected: ['disconnected', 'needs_setup', 'logged_out', 'locked', 'unlocked', 'error'],
  needs_setup: ['needs_setup', 'disconnected', 'logged_out', 'locked', 'unlocking', 'unlocked', 'error'],
  logged_out: ['logged_out', 'disconnected', 'needs_setup', 'locked', 'unlocked', 'error'],
  locked: ['locked', 'disconnected', 'needs_setup', 'logged_out', 'unlocking', 'unlocked', 'error'],
  unlocking: ['locked', 'unlocked', 'syncing', 'disconnected', 'error'],
  unlocked: ['unlocked', 'syncing', 'locked', 'logged_out', 'disconnected', 'error'],
  syncing: ['unlocked', 'locked', 'disconnected', 'error'],
  error: ['error', 'disconnected', 'needs_setup', 'logged_out', 'locked', 'unlocking', 'unlocked', 'syncing'],
};

/**
 * Comprueba si está permitido transicionar de `from` a `to`.
 */
export function canTransition(from: VaultStateName, to: VaultStateName): boolean {
  return TRANSITIONS[from].includes(to);
}

/**
 * Aplica una transición validada y devuelve el nuevo estado.
 * Lanza `Error` si la transición viola la tabla `TRANSITIONS`.
 */
export function transitionStatus(current: VaultStatus, next: VaultStatus): VaultStatus {
  if (!canTransition(current.state, next.state)) {
    throw new Error(`Transición de estado inválida: ${current.state} -> ${next.state}`);
  }
  return next;
}

/**
 * Traduce el DTO `AgentStatus` del backend al estado equivalente de la FSM.
 */
export function statusFromAgent(
  agentStatus: AgentStatus,
  currentLogins: LoginSummary[] = []
): VaultStatus {
  if (!agentStatus.has_pin && !agentStatus.logged_in) {
    return { state: 'needs_setup' };
  }
  if (agentStatus.locked) {
    return { state: 'locked' };
  }
  if (!agentStatus.logged_in) {
    return { state: 'logged_out' };
  }
  return { state: 'unlocked', logins: currentLogins };
}

const DISCONNECT_PATTERNS = [
  'socket no existe',
  'el agente no está corriendo',
  'agente no disponible',
  'connection refused',
  'econnrefused',
  'enoent',
  'no such file',
  'broken pipe',
  "reading 'invoke'",
  '__tauri_internals__',
];

/**
 * Detecta si el error proviene de una desconexión del socket IPC del agente.
 */
export function isDisconnectedError(message: string): boolean {
  const normalized = message.toLowerCase();
  return DISCONNECT_PATTERNS.some((pattern) => normalized.includes(pattern));
}

/**
 * Clasifica un error desconocido de IPC en `{ state: 'disconnected' }`,
 * `{ state: 'locked' }` o `{ state: 'error', message }`.
 */
export function classifyAgentError(err: unknown): VaultStatus {
  const message = err instanceof Error ? err.message : typeof err === 'string' ? err : String(err);
  if (isDisconnectedError(message)) {
    return { state: 'disconnected' };
  }
  const normalized = message.toLowerCase();
  if (normalized.includes('bóveda bloqueada') || /\blocked\b/.test(normalized)) {
    return { state: 'locked' };
  }
  return { state: 'error', message };
}
