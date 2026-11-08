<script lang="ts">
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";
  import { invoke } from "@tauri-apps/api/core";
  import {
    KeyRound,
    Star,
    Terminal,
    Search,
    Shield,
    AlertCircle,
    Copy,
    Check,
    Eye,
    EyeOff,
    RefreshCw,
  } from "lucide-svelte";
  import { vaultState } from "$lib/state/vault.svelte";

  type Tab = "all" | "favorites" | "ssh";

  interface LoginItem {
    id: string;
    name: string;
    username?: string;
  }

  interface LoginDetail {
    id: string;
    name: string;
    username?: string;
    password?: string;
    totp?: string;
  }

  let activeTab = $state<Tab>("all");
  let searchQuery = $state("");
  let copiedField = $state<string | null>(null);
  let showDetailPassword = $state(false);

  let logins = $state<LoginItem[]>([]);
  let selectedLogin = $state<LoginDetail | null>(null);
  let isLoading = $state(true);
  let isSyncing = $state(false);
  let errorMsg = $state<string | null>(null);

  let filteredLogins = $derived(
    logins.filter((item) => {
      const q = searchQuery.toLowerCase().trim();
      if (!q) return true;
      return (
        item.name.toLowerCase().includes(q) ||
        (item.username && item.username.toLowerCase().includes(q))
      );
    })
  );

  async function loadLogins() {
    isLoading = true;
    errorMsg = null;
    try {
      const [res] = await Promise.all([
        invoke<LoginItem[]>("list_logins"),
        new Promise((r) => setTimeout(r, 200)), // Retraso visual mínimo de 200ms
      ]);
      logins = Array.isArray(res) ? res : [];
      vaultState.logins = logins;

      if (selectedLogin && !logins.some((l) => l.name === selectedLogin?.name)) {
        selectedLogin = null;
      }
    } catch (err) {
      const errStr = typeof err === "string" ? err : String(err);
      if (errStr.toLowerCase().includes("lock") || errStr.toLowerCase().includes("bloquead")) {
        await goto("/login");
        return;
      }
      errorMsg = errStr;
      logins = [];
      vaultState.logins = [];
    } finally {
      isLoading = false;
    }
  }

  async function handleSync() {
    isSyncing = true;
    vaultState.isSyncing = true;
    errorMsg = null;
    try {
      await invoke("sync_vault");
      await loadLogins();
    } catch (err) {
      errorMsg = typeof err === "string" ? err : String(err);
    } finally {
      isSyncing = false;
      vaultState.isSyncing = false;
    }
  }

  async function handleSelectItem(name: string) {
    showDetailPassword = false;
    try {
      const detail = await invoke<LoginDetail>("get_login", { name });
      selectedLogin = detail;
      vaultState.selectedLogin = detail;
    } catch (err) {
      console.warn("Error al cargar detalle del login:", err);
    }
  }

  async function handleCopy(text: string, fieldId: string) {
    if (!text) return;
    try {
      await invoke("copy_to_clipboard", { text });
      copiedField = fieldId;
      setTimeout(() => {
        if (copiedField === fieldId) copiedField = null;
      }, 2000);
    } catch (e) {
      console.warn("Error al copiar al portapapeles:", e);
    }
  }

  onMount(async () => {
    try {
      const status = await invoke<{ locked?: boolean; has_pin?: boolean }>("get_agent_status");
      if (status.locked) {
        await goto("/login");
        return;
      }
    } catch (e) {
      console.warn("Error al verificar estado del agente:", e);
    }
    invoke("set_menu_state", { isLoggedIn: true }).catch(() => {});
    loadLogins();
  });
</script>

<div class="vault-container">
  <!-- 1. Sidebar (Izquierda) -->
  <aside class="vault-sidebar">
    <nav class="sidebar-nav">
      <button
        type="button"
        class="nav-item"
        class:active={activeTab === "all"}
        onclick={() => (activeTab = "all")}
      >
        <KeyRound size={18} />
        <span>Todos los Logins</span>
      </button>

      <button
        type="button"
        class="nav-item"
        class:active={activeTab === "favorites"}
        onclick={() => (activeTab = "favorites")}
      >
        <Star size={18} />
        <span>Favoritos</span>
      </button>

      <button
        type="button"
        class="nav-item"
        class:active={activeTab === "ssh"}
        onclick={() => (activeTab = "ssh")}
      >
        <Terminal size={18} />
        <span>Claves SSH</span>
      </button>
    </nav>
  </aside>

  <!-- 2. Lista de elementos (Centro) -->
  <section class="vault-list-section">
    <div class="search-bar">
      <div class="search-input-wrapper">
        <Search size={16} class="search-icon" />
        <input
          type="text"
          placeholder="Buscar logins o notas..."
          bind:value={searchQuery}
          aria-label="Buscar elementos de la bóveda"
        />
      </div>
      <button
        type="button"
        class="sync-btn"
        onclick={handleSync}
        disabled={isSyncing}
        title="Sincronizar con el servidor Bitwarden"
        aria-label="Sincronizar bóveda"
      >
        <span class="icon-wrap" class:spin={isSyncing}>
          <RefreshCw size={15} />
        </span>
        <span>{isSyncing ? "Sincronizando..." : "Sincronizar"}</span>
      </button>
    </div>

    <div class="list-content">
      {#if isLoading}
        <!-- Skeletons mientras carga (mínimo 200ms) -->
        <div class="skeletons-wrapper" aria-busy="true" aria-label="Cargando elementos">
          {#each [1, 2, 3] as _}
            <div class="skeleton-row">
              <div class="skeleton-icon"></div>
              <div class="skeleton-text-group">
                <div class="skeleton-line skeleton-title"></div>
                <div class="skeleton-line skeleton-subtitle"></div>
              </div>
            </div>
          {/each}
        </div>
      {:else if errorMsg}
        <div class="empty-state error-state">
          <AlertCircle size={32} class="empty-icon" color="var(--color-danger)" />
          <p class="empty-title">{errorMsg}</p>
          <button class="nav-item active retry-btn" onclick={loadLogins}>
            Reintentar
          </button>
        </div>
      {:else if logins.length === 0}
        <!-- Estado vacío: Sin logins -->
        <div class="empty-state">
          <KeyRound size={36} class="empty-icon" />
          <p class="empty-title">No hay logins en la bóveda. Sincroniza primero con el servidor.</p>
          <button
            type="button"
            class="sync-action-btn"
            onclick={handleSync}
            disabled={isSyncing}
          >
            <span class="icon-wrap" class:spin={isSyncing}>
              <RefreshCw size={15} />
            </span>
            <span>{isSyncing ? "Sincronizando..." : "Sincronizar con el Servidor"}</span>
          </button>
        </div>
      {:else if filteredLogins.length === 0}
        <div class="empty-state">
          <Search size={32} class="empty-icon" />
          <p class="empty-title">Sin resultados</p>
          <p class="empty-subtitle">No se encontró ningún acceso que coincida con "{searchQuery}".</p>
        </div>
      {:else}
        <!-- Lista de logins reales -->
        <div class="logins-list">
          {#each filteredLogins as login (login.id || login.name)}
            <button
              type="button"
              class="login-card-item"
              class:selected={selectedLogin?.name === login.name}
              onclick={() => handleSelectItem(login.name)}
            >
              <div class="login-card-icon">
                <KeyRound size={16} />
              </div>
              <div class="login-card-info">
                <span class="login-card-title">{login.name}</span>
                {#if login.username}
                  <span class="login-card-username">{login.username}</span>
                {/if}
              </div>
            </button>
          {/each}
        </div>
      {/if}
    </div>
  </section>

  <!-- 3. Panel de Detalles (Derecha) -->
  <main class="vault-details-section">
    {#if selectedLogin}
      <div class="detail-container">
        <div class="detail-header">
          <div class="detail-avatar">
            <KeyRound size={24} color="var(--color-primary)" />
          </div>
          <div class="detail-header-text">
            <h3>{selectedLogin.name}</h3>
            <span class="detail-tag">Login</span>
          </div>
        </div>

        <div class="detail-fields-list">
          {#if selectedLogin.username}
            <div class="detail-field">
              <span class="field-label">Nombre de usuario</span>
              <div class="field-box">
                <span class="field-value">{selectedLogin.username}</span>
                <button
                  type="button"
                  class="field-btn"
                  onclick={() => handleCopy(selectedLogin!.username!, "username")}
                  title="Copiar nombre de usuario"
                  aria-label="Copiar nombre de usuario"
                >
                  {#if copiedField === "username"}
                    <Check size={16} color="var(--color-success)" />
                  {:else}
                    <Copy size={16} />
                  {/if}
                </button>
              </div>
            </div>
          {/if}

          {#if selectedLogin.password}
            <div class="detail-field">
              <span class="field-label">Contraseña</span>
              <div class="field-box">
                <span class="field-value font-mono">
                  {showDetailPassword ? selectedLogin.password : "••••••••••••••••"}
                </span>
                <div class="field-actions">
                  <button
                    type="button"
                    class="field-btn"
                    onclick={() => (showDetailPassword = !showDetailPassword)}
                    title={showDetailPassword ? "Ocultar contraseña" : "Ver contraseña"}
                    aria-label={showDetailPassword ? "Ocultar contraseña" : "Ver contraseña"}
                  >
                    {#if showDetailPassword}
                      <EyeOff size={16} />
                    {:else}
                      <Eye size={16} />
                    {/if}
                  </button>
                  <button
                    type="button"
                    class="field-btn"
                    onclick={() => handleCopy(selectedLogin!.password!, "password")}
                    title="Copiar contraseña (se borra en 25s)"
                    aria-label="Copiar contraseña"
                  >
                    {#if copiedField === "password"}
                      <Check size={16} color="var(--color-success)" />
                    {:else}
                      <Copy size={16} />
                    {/if}
                  </button>
                </div>
              </div>
            </div>
          {/if}

          {#if selectedLogin.totp}
            <div class="detail-field">
              <span class="field-label">Código TOTP (2FA)</span>
              <div class="field-box">
                <span class="field-value font-mono">{selectedLogin.totp}</span>
                <button
                  type="button"
                  class="field-btn"
                  onclick={() => handleCopy(selectedLogin!.totp!, "totp")}
                  title="Copiar código TOTP"
                  aria-label="Copiar código TOTP"
                >
                  {#if copiedField === "totp"}
                    <Check size={16} color="var(--color-success)" />
                  {:else}
                    <Copy size={16} />
                  {/if}
                </button>
              </div>
            </div>
          {/if}
        </div>
      </div>
    {:else}
      <div class="details-placeholder">
        <Shield size={40} class="placeholder-icon" />
        <h3>Detalles del Acceso</h3>
        <p>Selecciona un login de la lista para ver su usuario, contraseña y opciones de seguridad.</p>
      </div>
    {/if}
  </main>
</div>

<style>
  .vault-container {
    display: flex;
    flex: 1;
    min-height: calc(100vh - 100px);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-sm);
    overflow: hidden;
    background-color: var(--color-bg);
    container-type: inline-size;
  }

  /* 1. Sidebar */
  .vault-sidebar {
    width: 220px;
    min-width: 180px;
    background-color: var(--color-bg-alt);
    border-right: 1px solid var(--color-border);
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    padding: var(--space-3);
  }

  .sidebar-nav {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .nav-item {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-2) var(--space-3);
    min-height: 38px;
    border-radius: var(--radius-md);
    border: none;
    background: transparent;
    color: var(--color-text);
    font-size: var(--font-size-sm);
    font-family: inherit;
    font-weight: 500;
    cursor: pointer;
    text-align: left;
    transition: background-color var(--transition-fast), color var(--transition-fast);
  }

  .nav-item:hover {
    background-color: var(--color-skeleton);
  }

  .nav-item:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: 1px;
  }

  .nav-item.active {
    background-color: color-mix(in srgb, var(--color-primary) 15%, transparent);
    color: var(--color-primary);
  }

  .retry-btn {
    margin-top: var(--space-3);
  }

  /* 2. Lista (Centro) */
  .vault-list-section {
    width: 360px;
    min-width: 300px;
    background-color: var(--color-bg);
    border-right: 1px solid var(--color-border);
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .search-bar {
    position: relative;
    padding: var(--space-2) var(--space-3);
    border-bottom: 1px solid var(--color-border);
    background-color: var(--color-bg-alt);
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }

  .search-input-wrapper {
    position: relative;
    flex: 1;
    display: flex;
    align-items: center;
  }

  .search-input-wrapper :global(.search-icon) {
    position: absolute;
    left: var(--space-2);
    color: var(--color-text-muted);
    pointer-events: none;
  }

  .search-input-wrapper input {
    width: 100%;
    box-sizing: border-box;
    padding: var(--space-2) var(--space-2) var(--space-2) var(--space-7);
    min-height: 36px;
    background-color: var(--color-bg);
    color: var(--color-text);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    font-size: var(--font-size-sm);
    font-family: inherit;
    transition: border-color var(--transition-fast);
  }

  .search-input-wrapper input:focus-visible,
  .search-input-wrapper input:focus {
    outline: 2px solid var(--color-primary);
    outline-offset: 1px;
    border-color: var(--color-primary);
  }

  .sync-btn {
    display: inline-flex;
    align-items: center;
    gap: var(--space-1);
    padding: var(--space-1) var(--space-3);
    min-height: 36px;
    border-radius: var(--radius-md);
    background-color: var(--color-bg);
    color: var(--color-text);
    border: 1px solid var(--color-border);
    font-size: var(--font-size-sm);
    font-family: inherit;
    font-weight: 500;
    cursor: pointer;
    transition: all var(--transition-fast);
    flex-shrink: 0;
  }

  .sync-btn:hover:not(:disabled) {
    background-color: var(--color-skeleton);
    color: var(--color-primary);
  }

  .sync-btn:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: 1px;
  }

  .sync-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .list-content {
    flex: 1;
    overflow-y: auto;
    padding: var(--space-2);
  }

  .logins-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .login-card-item {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-2) var(--space-3);
    min-height: 48px;
    border-radius: var(--radius-md);
    border: 1px solid transparent;
    background-color: transparent;
    text-align: left;
    cursor: pointer;
    font-family: inherit;
    color: var(--color-text);
    transition: background-color var(--transition-fast), border-color var(--transition-fast);
  }

  .login-card-item:hover {
    background-color: var(--color-bg-alt);
    border-color: var(--color-border);
  }

  .login-card-item:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: 1px;
  }

  .login-card-item.selected {
    background-color: color-mix(in srgb, var(--color-primary) 12%, transparent);
    border-color: var(--color-primary);
  }

  .login-card-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border-radius: var(--radius-sm);
    background-color: var(--color-bg-alt);
    color: var(--color-primary);
    border: 1px solid var(--color-border);
    flex-shrink: 0;
  }

  .login-card-info {
    display: flex;
    flex-direction: column;
    min-width: 0;
    flex: 1;
  }

  .login-card-title {
    font-size: var(--font-size-sm);
    font-weight: 500;
    color: var(--color-text);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .login-card-username {
    font-size: 0.75rem;
    color: var(--color-text-muted);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  /* Skeletons */
  .skeletons-wrapper {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .skeleton-row {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-3);
    background-color: var(--color-bg-alt);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
  }

  .skeleton-icon {
    width: 32px;
    height: 32px;
    border-radius: var(--radius-sm);
    background-color: var(--color-skeleton);
    animation: pulse 1.5s ease-in-out infinite;
    flex-shrink: 0;
  }

  .skeleton-text-group {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .skeleton-line {
    background-color: var(--color-skeleton);
    border-radius: var(--radius-sm);
    animation: pulse 1.5s ease-in-out infinite;
  }

  .skeleton-title {
    width: 60%;
    height: 14px;
  }

  .skeleton-subtitle {
    width: 40%;
    height: 10px;
  }

  @keyframes pulse {
    0%, 100% {
      opacity: 1;
    }
    50% {
      opacity: 0.4;
    }
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 280px;
    text-align: center;
    padding: var(--space-4);
    color: var(--color-text-muted);
  }

  .empty-state :global(.empty-icon) {
    color: var(--color-text-muted);
    opacity: 0.5;
    margin-bottom: var(--space-2);
  }

  .empty-title {
    margin: 0;
    font-size: var(--font-size-base);
    font-weight: 500;
    color: var(--color-text);
    max-width: 280px;
    line-height: 1.4;
    margin-bottom: var(--space-4);
  }

  .empty-subtitle {
    margin: var(--space-1) 0 var(--space-3) 0;
    font-size: var(--font-size-sm);
    color: var(--color-text-muted);
    max-width: 240px;
  }

  .sync-action-btn {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-2) var(--space-4);
    min-height: 38px;
    border-radius: var(--radius-md);
    background-color: var(--color-primary);
    color: var(--color-primary-text);
    border: 1px solid var(--color-primary);
    font-size: var(--font-size-sm);
    font-family: inherit;
    font-weight: 500;
    cursor: pointer;
    transition: all var(--transition-fast);
  }

  .sync-action-btn:hover:not(:disabled) {
    background-color: var(--color-primary-hover);
  }

  .sync-action-btn:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: 2px;
  }

  .sync-action-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .icon-wrap {
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }

  /* 3. Detalles (Derecha) */
  .vault-details-section {
    flex: 1;
    background-color: var(--color-bg-alt);
    display: flex;
    align-items: flex-start;
    justify-content: center;
    padding: var(--space-6);
    overflow-y: auto;
  }

  .detail-container {
    width: 100%;
    max-width: 500px;
    display: flex;
    flex-direction: column;
    gap: var(--space-6);
  }

  .detail-header {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding-bottom: var(--space-4);
    border-bottom: 1px solid var(--color-border);
  }

  .detail-avatar {
    width: 48px;
    height: 48px;
    border-radius: var(--radius-md);
    background-color: var(--color-bg);
    border: 1px solid var(--color-border);
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: var(--shadow-sm);
  }

  .detail-header-text h3 {
    margin: 0;
    font-size: var(--font-size-lg);
    color: var(--color-text);
  }

  .detail-tag {
    font-size: 0.75rem;
    color: var(--color-text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .detail-fields-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .detail-field {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .field-label {
    font-size: var(--font-size-sm);
    font-weight: 500;
    color: var(--color-text-muted);
  }

  .field-box {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--space-2) var(--space-3);
    min-height: 40px;
    background-color: var(--color-bg);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    gap: var(--space-2);
  }

  .field-value {
    font-size: var(--font-size-base);
    color: var(--color-text);
    word-break: break-all;
    flex: 1;
  }

  .font-mono {
    font-family: monospace;
    letter-spacing: 0.08em;
  }

  .field-actions {
    display: flex;
    align-items: center;
    gap: var(--space-1);
  }

  .field-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    background: transparent;
    border: none;
    color: var(--color-text-muted);
    border-radius: var(--radius-sm);
    cursor: pointer;
    transition: color var(--transition-fast), background-color var(--transition-fast);
  }

  .field-btn:hover {
    color: var(--color-text);
    background-color: var(--color-skeleton);
  }

  .field-btn:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: 1px;
  }

  .details-placeholder {
    max-width: 360px;
    text-align: center;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-2);
    margin: auto;
  }

  .details-placeholder :global(.placeholder-icon) {
    color: var(--color-primary);
    opacity: 0.4;
    margin-bottom: var(--space-2);
  }

  .details-placeholder h3 {
    margin: 0;
    font-size: var(--font-size-lg);
    color: var(--color-text);
  }

  .details-placeholder p {
    margin: 0;
    font-size: var(--font-size-sm);
    color: var(--color-text-muted);
    line-height: 1.5;
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

  /* Responsive: Container Query */
  @container (max-width: 768px) {
    .vault-container {
      flex-direction: column;
      height: auto;
      min-height: calc(100vh - 65px);
    }

    .vault-sidebar {
      width: 100%;
      min-width: 100%;
      border-right: none;
      border-bottom: 1px solid var(--color-border);
    }

    .sidebar-nav {
      flex-direction: row;
      overflow-x: auto;
    }

    .vault-list-section {
      width: 100%;
      min-width: 100%;
      border-right: none;
      border-bottom: 1px solid var(--color-border);
      max-height: 350px;
    }

    .vault-details-section {
      min-height: 250px;
    }
  }
</style>
