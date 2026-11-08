import { invoke } from '@tauri-apps/api/core';

export interface LoginItem {
  id: string;
  name: string;
  username: string;
}

export interface LoginDetail {
  id: string;
  name: string;
  username?: string;
  password?: string;
  totp?: string;
}

class VaultState {
  logins = $state<LoginItem[]>([]);
  selectedLogin = $state<LoginDetail | null>(null);
  isLoading = $state(false);
  isSyncing = $state(false);
  isLocking = $state(false);
  error = $state<string | null>(null);

  async loadLogins() {
    this.isLoading = true;
    this.error = null;
    try {
      const [res] = await Promise.all([
        invoke<LoginItem[]>('list_logins'),
        new Promise((r) => setTimeout(r, 250)), // Retraso visual mínimo de 250ms (Sección 2)
      ]);
      this.logins = Array.isArray(res) ? res : [];
      // Si el elemento seleccionado ya no existe en la lista, limpiarlo
      if (this.selectedLogin && !this.logins.some((l) => l.name === this.selectedLogin?.name)) {
        this.selectedLogin = null;
      }
    } catch (err) {
      this.error = typeof err === 'string' ? err : String(err);
      this.logins = [];
    } finally {
      this.isLoading = false;
    }
  }

  async sync() {
    this.isSyncing = true;
    this.error = null;
    try {
      await invoke('sync_vault');
      await this.loadLogins();
    } catch (err) {
      this.error = typeof err === 'string' ? err : String(err);
    } finally {
      this.isSyncing = false;
    }
  }

  async selectLogin(name: string) {
    try {
      const detail = await invoke<LoginDetail>('get_login', { name });
      this.selectedLogin = detail;
    } catch (err) {
      console.warn('Error al obtener login:', err);
    }
  }

  async lock(navigate: () => Promise<void> | void) {
    this.isLocking = true;
    try {
      await invoke('lock_vault');
    } catch (e) {
      console.warn('Error al bloquear en el agente:', e);
    }
    try {
      await invoke('set_menu_state', { isLoggedIn: false });
    } catch (e) {
      console.warn('No se pudo actualizar el menú:', e);
    }
    this.logins = [];
    this.selectedLogin = null;
    this.isLocking = false;
    await navigate();
  }
}

export const vaultState = new VaultState();

