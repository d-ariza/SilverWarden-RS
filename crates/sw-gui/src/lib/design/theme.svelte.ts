import './tokens.css';
import './themes/fluent.css';
import './themes/cupertino.css';
import './themes/breeze.css';
import { invoke } from '@tauri-apps/api/core';

export type ThemeName = 'fluent' | 'cupertino' | 'breeze';
export type ThemeMode = 'light' | 'dark';

class ThemeState {
  current = $state<ThemeName>('fluent');
  mode = $state<ThemeMode>('light');
  private isLoaded = false;

  constructor() {
    if (typeof window !== 'undefined' && window.matchMedia) {
      this.mode = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    this.apply();
    if (typeof window !== 'undefined') {
      this.initFromBackend();
    }
  }

  private async initFromBackend() {
    if (typeof window === 'undefined') return;
    try {
      const raw = await invoke<string>('load_settings');
      if (raw) {
        const settings = JSON.parse(raw);
        if (settings.theme) this.current = settings.theme;
        if (settings.mode) this.mode = settings.mode;
        this.apply();
      }
    } catch (e) {
      console.warn('No se pudo cargar la configuración de tema:', e);
    } finally {
      this.isLoaded = true;
    }
  }

  private async persist() {
    if (typeof window === 'undefined' || !this.isLoaded) return;
    try {
      await invoke('save_settings', { theme: this.current, mode: this.mode });
    } catch (e) {
      console.warn('No se pudo guardar la configuración de tema:', e);
    }
  }

  setTheme(theme: ThemeName) {
    this.current = theme;
    this.apply();
    this.persist();
  }

  toggleMode() {
    this.mode = this.mode === 'light' ? 'dark' : 'light';
    this.apply();
    this.persist();
  }

  apply() {
    if (typeof document !== 'undefined') {
      document.documentElement.setAttribute('data-theme', this.current);
      document.documentElement.setAttribute('data-mode', this.mode);
    }
  }
}

export const themeState = new ThemeState();
