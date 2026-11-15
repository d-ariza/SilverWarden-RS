import { invoke } from '@tauri-apps/api/core';
import type { AgentStatus } from '$lib/types/generated/AgentStatus';
import type { ConfigView } from '$lib/types/generated/ConfigView';
import type { LoginDetail } from '$lib/types/generated/LoginDetail';
import type { LoginSummary } from '$lib/types/generated/LoginSummary';
import type { PinChangeResult } from '$lib/types/generated/PinChangeResult';
import type { SshKeySummary } from '$lib/types/generated/SshKeySummary';
import type { SyncResult } from '$lib/types/generated/SyncResult';

/**
 * Gateway tipado único hacia los comandos IPC de Tauri.
 * Centraliza todas las invocaciones y mapea directamente a los DTOs generados.
 */
export const agent = {
  getStatus(): Promise<AgentStatus> {
    return invoke<AgentStatus>('get_agent_status');
  },

  unlock(pin: string): Promise<string> {
    return invoke<string>('unlock_vault', { pin });
  },

  lock(): Promise<string> {
    return invoke<string>('lock_vault');
  },

  sync(): Promise<SyncResult> {
    return invoke<SyncResult>('sync_vault');
  },

  listLogins(): Promise<LoginSummary[]> {
    return invoke<LoginSummary[]>('list_logins');
  },

  getLogin(name: string): Promise<LoginDetail> {
    return invoke<LoginDetail>('get_login', { name });
  },

  listSshKeys(): Promise<SshKeySummary[]> {
    return invoke<SshKeySummary[]>('list_ssh_keys');
  },

  importSshKey(name: string, pem: string): Promise<SshKeySummary> {
    return invoke<SshKeySummary>('import_ssh_key', { name, pem });
  },

  newSshKey(name: string, keyType: string): Promise<SshKeySummary> {
    return invoke<SshKeySummary>('new_ssh_key', { name, keyType });
  },

  deleteSshKey(id: string): Promise<string> {
    return invoke<string>('delete_ssh_key', { id });
  },

  pinSet(pin: string): Promise<PinChangeResult> {
    return invoke<PinChangeResult>('pin_set', { pin });
  },

  pinUpdate(oldPin: string, newPin: string): Promise<PinChangeResult> {
    return invoke<PinChangeResult>('pin_update', { oldPin, newPin });
  },

  getConfig(): Promise<ConfigView> {
    return invoke<ConfigView>('get_config');
  },

  setConfig(config: ConfigView): Promise<ConfigView> {
    return invoke<ConfigView>('set_config', { config });
  },

  copyToClipboard(text: string): Promise<void> {
    return invoke<void>('copy_to_clipboard', { text });
  },

  setMenuState(isLoggedIn: boolean): Promise<void> {
    return invoke<void>('set_menu_state', { isLoggedIn });
  },

  saveSettings(theme: string, mode: string): Promise<void> {
    return invoke<void>('save_settings', { theme, mode });
  },

  loadSettings(): Promise<string> {
    return invoke<string>('load_settings');
  },
};
