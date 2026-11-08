<script lang="ts">
  import "../lib/design/theme.svelte";
  import { themeState } from "../lib/design/theme.svelte";
  import { page } from "$app/state";
  import { goto } from "$app/navigation";
  import { onMount } from "svelte";
  import { listen } from "@tauri-apps/api/event";
  import { Lock, RefreshCw } from "lucide-svelte";
  import { vaultState } from "$lib/state/vault.svelte";

  let { children } = $props();
  let isVault = $derived(page.url.pathname.startsWith("/vault"));

  onMount(() => {
    let unlistenPromise = listen("vault-locked", () => {
      vaultState.logins = [];
      vaultState.selectedLogin = null;
      goto("/login");
    });

    return () => {
      unlistenPromise.then((unlisten) => unlisten()).catch(() => {});
    };
  });
</script>

<div class="app-container">
  <header class="topbar">
    <div class="logo">SilverWarden</div>
    <div class="topbar-actions">
      {#if isVault}
        <div class="vault-topbar-controls">
          <button
            type="button"
            class="btn-topbar btn-secondary"
            onclick={() => vaultState.sync()}
            disabled={vaultState.isSyncing}
            title="Sincronizar bóveda con el agente"
            aria-label="Sincronizar bóveda"
          >
            <span class="icon-wrap" class:spin={vaultState.isSyncing}>
              <RefreshCw size={15} />
            </span>
            <span>{vaultState.isSyncing ? "Sincronizando..." : "Sincronizar"}</span>
          </button>

          <button
            type="button"
            class="btn-topbar btn-danger"
            onclick={() => vaultState.lock(() => goto("/login"))}
            disabled={vaultState.isLocking}
            title="Bloquear la bóveda"
            aria-label="Bloquear bóveda"
          >
            <Lock size={15} />
            <span>Bloquear</span>
          </button>
        </div>
      {/if}

      <div class="theme-controls">
        <select
          bind:value={themeState.current}
          onchange={() => themeState.setTheme(themeState.current)}
          aria-label="Seleccionar tema visual"
        >
          <option value="fluent">Windows 11 (Fluent)</option>
          <option value="cupertino">macOS (Cupertino)</option>
          <option value="breeze">KDE Plasma (Breeze)</option>
        </select>
        <button
          onclick={() => themeState.toggleMode()}
          aria-label="Alternar modo claro u oscuro"
        >
          {themeState.mode === "light" ? "🌙 Oscuro" : "☀️ Claro"}
        </button>
      </div>
    </div>
  </header>

  <main class="content">
    {@render children()}
  </main>
</div>

<style>
  /* Para estilos globales en Svelte 5, se usa :global */
  :global(body) {
    margin: 0;
    padding: 0;
    font-family: var(--font-family);
    background-color: var(--color-bg);
    color: var(--color-text);
    transition:
      background-color var(--transition-fast),
      color var(--transition-fast);
  }

  .app-container {
    display: flex;
    flex-direction: column;
    min-height: 100vh;
  }

  .topbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--space-3) var(--space-4);
    background-color: var(--color-bg-alt);
    background-color: color-mix(in srgb, var(--color-bg-alt) 80%, transparent);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--color-border);
    box-shadow: var(--shadow-sm);
    position: sticky;
    top: 0;
    z-index: 10;
  }

  .logo {
    font-weight: bold;
    font-size: var(--font-size-lg);
    color: var(--color-primary);
  }

  .topbar-actions {
    display: flex;
    gap: var(--space-4);
    align-items: center;
  }

  .vault-topbar-controls {
    display: flex;
    gap: var(--space-2);
    align-items: center;
  }

  .btn-topbar {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: var(--space-2);
    padding: var(--space-1) var(--space-3);
    min-height: 36px;
    border-radius: var(--radius-md);
    font-size: var(--font-size-sm);
    font-family: inherit;
    font-weight: 500;
    cursor: pointer;
    transition: all var(--transition-fast);
  }

  .btn-topbar:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: 2px;
  }

  .btn-topbar:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .btn-danger {
    background-color: color-mix(in srgb, var(--color-danger) 12%, transparent);
    color: var(--color-danger);
    border: 1px solid var(--color-danger);
  }

  .btn-danger:hover:not(:disabled) {
    background-color: var(--color-danger);
    color: #ffffff;
  }

  .btn-secondary {
    background-color: var(--color-bg);
    color: var(--color-text);
    border: 1px solid var(--color-border);
  }

  .btn-secondary:hover:not(:disabled) {
    background-color: var(--color-skeleton);
  }

  .icon-wrap {
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }

  .spin {
    animation: spin 1s linear infinite;
  }

  @keyframes spin {
    from {
      transform: rotate(0deg);
    }
    to {
      transform: rotate(360deg);
    }
  }

  .theme-controls {
    display: flex;
    gap: var(--space-2);
    align-items: center;
  }

  .theme-controls select,
  .theme-controls button {
    padding: var(--space-1) var(--space-2);
    min-height: 36px;
    border-radius: var(--radius-md);
    border: 1px solid var(--color-border);
    background-color: var(--color-bg);
    color: var(--color-text);
    font-family: inherit;
    cursor: pointer;
    transition: all var(--transition-fast);
  }

  .theme-controls select {
    width: 160px;
    min-width: 160px;
    text-align: center;
  }

  .theme-controls button {
    width: 120px;
    min-width: 120px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    text-align: center;
  }

  .theme-controls button:hover,
  .theme-controls select:hover {
    background-color: var(--color-skeleton);
  }

  .theme-controls button:focus-visible,
  .theme-controls select:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: 2px;
  }

  .content {
    flex: 1;
    padding: var(--space-4);
    display: flex;
    flex-direction: column;
  }

  :global(select) {
    background-color: var(--color-bg-alt);
    color: var(--color-text);
    border: 1px solid var(--color-border);
    appearance: none; /* Crucial */
    padding: var(--space-1) var(--space-6) var(--space-1) var(--space-2);
    border-radius: var(--radius-sm);
    background-image: url("data:image/svg+xml;charset=US-ASCII,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%22292.4%22%20height%3D%22292.4%22%3E%3Cpath%20fill%3D%22%23666%22%20d%3D%22M287%2069.4a17.6%2017.6%200%200%200-13-5.4H18.4c-5%200-9.3%201.8-12.9%205.4A17.6%2017.6%200%200%200%200%2082.2c0%205%201.8%209.3%205.4%2012.9l128%20127.9c3.6%203.6%207.8%205.4%2012.8%205.4s9.2-1.8%2012.8-5.4L287%2095c3.5-3.5%205.4-7.8%205.4-12.8%200-5-1.9-9.2-5.5-12.8z%22%2F%3E%3C%2Fsvg%3E");
    background-repeat: no-repeat;
    background-position: right var(--space-2) top 50%;
    background-size: 10px;
  }

  :global(option) {
    background-color: var(--color-bg-alt);
    color: var(--color-text);
  }
</style>
