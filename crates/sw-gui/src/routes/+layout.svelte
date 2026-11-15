<script lang="ts">
  import "../lib/design/theme.svelte";
  import { themeState } from "../lib/design/theme.svelte";
  import { page } from "$app/state";
  import { goto } from "$app/navigation";
  import { onMount } from "svelte";
  import { listen } from "@tauri-apps/api/event";
  import { Lock, RefreshCw, KeyRound, Terminal, Settings } from "lucide-svelte";
  import { vaultState } from "$lib/state/vault.svelte";

  let { children } = $props();

  let pathname = $derived(page.url.pathname);
  let syncing = $derived(vaultState.status.state === "syncing");
  let isUnlocked = $derived(
    vaultState.status.state === "unlocked" || vaultState.status.state === "syncing"
  );
  let showWorkspaceNav = $derived(
    isUnlocked ||
      pathname.startsWith("/vault") ||
      pathname.startsWith("/ssh") ||
      pathname.startsWith("/settings")
  );
  let showSyncAndLock = $derived(
    pathname.startsWith("/vault") || pathname.startsWith("/ssh") || isUnlocked
  );

  onMount(() => {
    if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) {
      return;
    }

    let unlistenPromise = listen("vault-locked", () => {
      vaultState.handleExternalLock();
      goto("/login");
    });

    return () => {
      unlistenPromise.then((unlisten) => unlisten()).catch(() => {});
    };
  });
</script>

<div class="app-container">
  <header class="topbar">
    <div class="topbar-brand">
      <a href="/" class="logo">SilverWarden</a>

      <nav class="topbar-nav" aria-label="Navegación principal">
        {#if showWorkspaceNav}
          <a
            href="/vault"
            class="nav-link"
            aria-current={pathname.startsWith("/vault") ? "page" : undefined}
          >
            <KeyRound size={15} />
            <span>Bóveda</span>
          </a>
          <a
            href="/ssh"
            class="nav-link"
            aria-current={pathname.startsWith("/ssh") ? "page" : undefined}
          >
            <Terminal size={15} />
            <span>Claves SSH</span>
          </a>
        {/if}
        <a
          href="/settings"
          class="nav-link"
          aria-current={pathname.startsWith("/settings") ? "page" : undefined}
        >
          <Settings size={15} />
          <span>Ajustes</span>
        </a>
      </nav>
    </div>

    <div class="topbar-actions">
      {#if showSyncAndLock}
        <div class="vault-topbar-controls">
          <button
            type="button"
            class="btn-topbar btn-secondary"
            onclick={() => vaultState.sync()}
            disabled={syncing || !isUnlocked}
            title="Sincronizar bóveda con el agente"
            aria-label="Sincronizar bóveda"
          >
            <span class="icon-wrap" class:spin={syncing}>
              <RefreshCw size={15} />
            </span>
            <span>{syncing ? "Sincronizando..." : "Sincronizar"}</span>
          </button>

          <button
            type="button"
            class="btn-topbar btn-danger"
            onclick={() => vaultState.lock(() => goto("/login"))}
            disabled={vaultState.status.state === "locked" || syncing}
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
          type="button"
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
    gap: var(--space-3);
    flex-wrap: wrap;
    padding: var(--space-2) var(--space-4);
    background-color: var(--color-bg-alt);
    background-color: color-mix(in srgb, var(--color-bg-alt) 85%, transparent);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--color-border);
    box-shadow: var(--shadow-sm);
    position: sticky;
    top: 0;
    z-index: 10;
  }

  .topbar-brand {
    display: flex;
    align-items: center;
    gap: var(--space-4);
  }

  .logo {
    font-weight: 700;
    font-size: var(--font-size-lg);
    color: var(--color-primary);
    text-decoration: none;
  }

  .topbar-nav {
    display: flex;
    align-items: center;
    gap: var(--space-1);
  }

  .nav-link {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-1) var(--space-3);
    min-height: 36px;
    border-radius: var(--radius-md);
    font-size: var(--font-size-sm);
    font-weight: 500;
    color: var(--color-text-muted);
    text-decoration: none;
    border: 1px solid transparent;
    transition: background-color var(--transition-fast), color var(--transition-fast), border-color var(--transition-fast);
  }

  .nav-link:hover {
    background-color: var(--color-skeleton);
    color: var(--color-text);
  }

  .nav-link[aria-current="page"] {
    background-color: color-mix(in srgb, var(--color-primary) 12%, transparent);
    color: var(--color-primary);
    border-color: color-mix(in srgb, var(--color-primary) 30%, transparent);
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

  .btn-topbar:focus-visible,
  .nav-link:focus-visible {
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
    color: var(--color-danger-text);
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
  }

  :global(.spin) {
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
  }

  select,
  .theme-controls button {
    padding: var(--space-1) var(--space-2);
    min-height: 36px;
    border-radius: var(--radius-md);
    border: 1px solid var(--color-border);
    background-color: var(--color-bg);
    color: var(--color-text);
    font-family: inherit;
    font-size: var(--font-size-sm);
    cursor: pointer;
  }

  select:focus-visible,
  .theme-controls button:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: 2px;
  }

  .content {
    flex: 1;
    padding: var(--space-6);
    max-width: 1200px;
    width: 100%;
    margin: 0 auto;
    box-sizing: border-box;
  }
</style>
