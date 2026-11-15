import { agent } from '$lib/api/agent';
import type { LoginDetail } from '$lib/types/generated/LoginDetail';
import type { LoginSummary } from '$lib/types/generated/LoginSummary';
import {
  canTransition,
  classifyAgentError,
  statusFromAgent,
  transitionStatus,
} from './transitions';
import type { VaultStateName, VaultStatus } from './types';

class VaultState {
  status = $state<VaultStatus>({ state: 'disconnected' });
  selectedLogin = $state<LoginDetail | null>(null);

  get logins(): LoginSummary[] {
    return this.status.state === 'unlocked' || this.status.state === 'syncing'
      ? this.status.logins
      : [];
  }

  get stateName(): VaultStateName {
    return this.status.state;
  }

  get errorMessage(): string | null {
    return this.status.state === 'error' ? this.status.message : null;
  }

  clearErrorTo(target: 'locked' | 'unlocked' | 'disconnected'): void {
    if (this.status.state !== 'error') return;
    const next: VaultStatus =
      target === 'unlocked'
        ? { state: 'unlocked', logins: this.logins }
        : { state: target };
    if (canTransition(this.status.state, next.state)) {
      this.status = transitionStatus(this.status, next);
    }
  }

  async refreshStatus(): Promise<VaultStatus> {
    try {
      const res = await agent.getStatus();
      const next = statusFromAgent(res, this.logins);
      if (next.state !== 'unlocked' && next.state !== 'syncing') {
        this.selectedLogin = null;
      }
      if (canTransition(this.status.state, next.state)) {
        this.status = transitionStatus(this.status, next);
      }
    } catch (err) {
      const next = classifyAgentError(err);
      if (next.state !== 'error') {
        this.selectedLogin = null;
      }
      if (canTransition(this.status.state, next.state)) {
        this.status = transitionStatus(this.status, next);
      }
    }
    return this.status;
  }

  async unlock(pin: string): Promise<boolean> {
    if (!canTransition(this.status.state, 'unlocking')) {
      return false;
    }
    this.status = transitionStatus(this.status, { state: 'unlocking' });
    try {
      const result = await agent.unlock(pin);
      if (result === 'unlocked') {
        this.status = transitionStatus(this.status, { state: 'unlocked', logins: [] });
        await agent.setMenuState(true).catch((e) => {
          console.warn('No se pudo actualizar el menú:', e);
        });
        await agent.sync().catch((e) => {
          console.warn('Error en sync tras desbloqueo:', e);
        });
        await this.loadLogins();
        return this.status.state === 'unlocked' || this.status.state === 'syncing';
      }
      this.status = transitionStatus(this.status, {
        state: 'error',
        message: `Respuesta inesperada del agente: ${result}`,
      });
      return false;
    } catch (err) {
      this.status = transitionStatus(this.status, classifyAgentError(err));
      return false;
    }
  }

  async loadLogins(): Promise<void> {
    if (!canTransition(this.status.state, 'syncing')) {
      return;
    }
    const previousLogins = this.logins;
    this.status = transitionStatus(this.status, { state: 'syncing', logins: previousLogins });
    try {
      const [res] = await Promise.all([
        agent.listLogins(),
        new Promise((r) => setTimeout(r, 250)), // Retraso visual mínimo de 250ms (Sección 2)
      ]);
      const list = Array.isArray(res) ? res : [];
      if (this.selectedLogin && !list.some((l) => l.name === this.selectedLogin?.name)) {
        this.selectedLogin = null;
      }
      this.status = transitionStatus(this.status, { state: 'unlocked', logins: list });
    } catch (err) {
      const next = classifyAgentError(err);
      if (next.state !== 'error') {
        this.selectedLogin = null;
      }
      this.status = transitionStatus(this.status, next);
    }
  }

  async sync(): Promise<void> {
    if (!canTransition(this.status.state, 'syncing')) {
      return;
    }
    const previousLogins = this.logins;
    this.status = transitionStatus(this.status, { state: 'syncing', logins: previousLogins });
    try {
      await agent.sync();
      const [res] = await Promise.all([
        agent.listLogins(),
        new Promise((r) => setTimeout(r, 250)),
      ]);
      const list = Array.isArray(res) ? res : [];
      if (this.selectedLogin && !list.some((l) => l.name === this.selectedLogin?.name)) {
        this.selectedLogin = null;
      }
      this.status = transitionStatus(this.status, { state: 'unlocked', logins: list });
    } catch (err) {
      const next = classifyAgentError(err);
      if (next.state !== 'error') {
        this.selectedLogin = null;
      }
      this.status = transitionStatus(this.status, next);
    }
  }

  async selectLogin(name: string): Promise<void> {
    try {
      this.selectedLogin = await agent.getLogin(name);
    } catch (err) {
      const next = classifyAgentError(err);
      if ((next.state === 'disconnected' || next.state === 'locked') && canTransition(this.status.state, next.state)) {
        this.selectedLogin = null;
        this.status = transitionStatus(this.status, next);
      } else {
        console.warn('Error al obtener login:', err);
      }
    }
  }

  async lock(navigate: () => Promise<void> | void): Promise<void> {
    try {
      await agent.lock();
    } catch (e) {
      console.warn('Error al bloquear en el agente:', e);
    }
    try {
      await agent.setMenuState(false);
    } catch (e) {
      console.warn('No se pudo actualizar el menú:', e);
    }
    this.selectedLogin = null;
    if (canTransition(this.status.state, 'locked')) {
      this.status = transitionStatus(this.status, { state: 'locked' });
    }
    await navigate();
  }

  handleExternalLock(): void {
    this.selectedLogin = null;
    if (canTransition(this.status.state, 'locked')) {
      this.status = transitionStatus(this.status, { state: 'locked' });
    }
  }
}

export const vaultState = new VaultState();
