import { describe, expect, it } from 'vitest';
import {
  TRANSITIONS,
  canTransition,
  classifyAgentError,
  isDisconnectedError,
  statusFromAgent,
  transitionStatus,
} from './transitions';
import type { LoginSummary } from '$lib/types/generated/LoginSummary';
import type { VaultStateName, VaultStatus } from './types';

const SAMPLE_LOGIN: LoginSummary = {
  id: 'id-1',
  name: 'GitHub',
  username: 'alice@example.com',
};

function makeStatus(state: VaultStateName): VaultStatus {
  switch (state) {
    case 'unlocked':
      return { state: 'unlocked', logins: [SAMPLE_LOGIN] };
    case 'syncing':
      return { state: 'syncing', logins: [SAMPLE_LOGIN] };
    case 'error':
      return { state: 'error', message: 'Fallo de prueba' };
    case 'disconnected':
    case 'needs_setup':
    case 'logged_out':
    case 'locked':
    case 'unlocking':
      return { state };
  }
}

describe('Vault FSM transitions', () => {
  const allStates = Object.keys(TRANSITIONS) as VaultStateName[];

  it('cubre exactamente los 8 estados especificados', () => {
    expect(allStates.sort()).toEqual(
      [
        'disconnected',
        'error',
        'locked',
        'logged_out',
        'needs_setup',
        'syncing',
        'unlocked',
        'unlocking',
      ].sort()
    );
  });

  it('permite todas las transiciones declaradas en TRANSITIONS', () => {
    for (const from of allStates) {
      const current = makeStatus(from);
      for (const to of TRANSITIONS[from]) {
        const next = makeStatus(to);
        expect(canTransition(from, to)).toBe(true);
        expect(transitionStatus(current, next)).toEqual(next);
      }
    }
  });

  it('rechaza todas las transiciones no declaradas en TRANSITIONS', () => {
    for (const from of allStates) {
      const current = makeStatus(from);
      const allowed = new Set(TRANSITIONS[from]);
      for (const to of allStates) {
        if (allowed.has(to)) continue;
        const next = makeStatus(to);
        expect(canTransition(from, to)).toBe(false);
        expect(() => transitionStatus(current, next)).toThrow(/Transición de estado inválida/);
      }
    }
  });

  it('impide invariantes críticas de negocio (sync sin desbloquear, doble unlock/sync)', () => {
    expect(canTransition('locked', 'syncing')).toBe(false);
    expect(canTransition('disconnected', 'syncing')).toBe(false);
    expect(canTransition('disconnected', 'unlocking')).toBe(false);
    expect(canTransition('needs_setup', 'syncing')).toBe(false);
    expect(canTransition('logged_out', 'syncing')).toBe(false);
    expect(canTransition('logged_out', 'unlocking')).toBe(false);
    expect(canTransition('unlocked', 'unlocking')).toBe(false);
    expect(canTransition('unlocked', 'needs_setup')).toBe(false);
    expect(canTransition('unlocking', 'unlocking')).toBe(false);
    expect(canTransition('syncing', 'syncing')).toBe(false);
  });

  it('traduce AgentStatus a VaultStatus correctamente', () => {
    expect(
      statusFromAgent({
        locked: false,
        has_pin: false,
        logged_in: false,
        pin_cached: false,
        pin_cached_remaining_secs: 0,
        version: '0.1.0',
      })
    ).toEqual({ state: 'needs_setup' });

    expect(
      statusFromAgent({
        locked: true,
        has_pin: true,
        logged_in: false,
        pin_cached: false,
        pin_cached_remaining_secs: 0,
        version: '0.1.0',
      })
    ).toEqual({ state: 'locked' });

    expect(
      statusFromAgent({
        locked: false,
        has_pin: true,
        logged_in: false,
        pin_cached: false,
        pin_cached_remaining_secs: 0,
        version: '0.1.0',
      })
    ).toEqual({ state: 'logged_out' });

    expect(
      statusFromAgent(
        {
          locked: false,
          has_pin: true,
          logged_in: true,
          pin_cached: true,
          pin_cached_remaining_secs: 120,
          version: '0.1.0',
        },
        [SAMPLE_LOGIN]
      )
    ).toEqual({ state: 'unlocked', logins: [SAMPLE_LOGIN] });
  });

  it('distingue errores de desconexión IPC de errores del agente o bloqueo', () => {
    expect(isDisconnectedError('El agente no está corriendo (socket no existe).')).toBe(true);
    expect(isDisconnectedError('Agente no disponible: Connection refused (os error 111)')).toBe(true);
    expect(isDisconnectedError('El PIN es incorrecto, inténtalo de nuevo.')).toBe(false);

    expect(classifyAgentError('El agente no está corriendo (socket no existe).')).toEqual({
      state: 'disconnected',
    });
    expect(classifyAgentError('Bóveda bloqueada. Desbloquea primero.')).toEqual({
      state: 'locked',
    });
    expect(classifyAgentError('El PIN es incorrecto, inténtalo de nuevo.')).toEqual({
      state: 'error',
      message: 'El PIN es incorrecto, inténtalo de nuevo.',
    });
  });
});
