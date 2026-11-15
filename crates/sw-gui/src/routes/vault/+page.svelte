<script lang="ts">
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";
  import { agent } from "$lib/api/agent";
  import {
    KeyRound,
    Star,
    Terminal,
    Settings,
    Search,
    Shield,
    AlertCircle,
    WifiOff,
    Copy,
    Check,
    Eye,
    EyeOff,
    RefreshCw,
  } from "lucide-svelte";
  import { vaultState } from "$lib/state/vault.svelte";

  type Tab = "all" | "favorites";

  let activeTab = $state<Tab>("all");
  let searchQuery = $state("");
  let copiedField = $state<string | null>(null);
  let showDetailPassword = $state(false);
  let hasCheckedAgent = $state(false);

  let syncing = $derived(vaultState.status.state === "syncing");
  let isDisconnected = $derived(vaultState.status.state === "disconnected");
  let errorMsg = $derived(
    vaultState.status.state === "error" ? vaultState.status.message : null
  );

  let filteredLogins = $derived(
    vaultState.logins.filter((item) => {
      const q = searchQuery.toLowerCase().trim();
      if (!q) return true;
      return (
        item.name.toLowerCase().includes(q) ||
        (item.username && item.username.toLowerCase().includes(q))
      );
    })
  );

  async function initVault() {
    hasCheckedAgent = false;
    const status = await vaultState.refreshStatus();
    if (status.state === "locked" || status.state === "logged_out") {
      hasCheckedAgent = true;
      await goto("/login");
      return;
    }
    if (status.state === "needs_setup") {
      hasCheckedAgent = true;
      await goto("/setup");
      return;
    }
    if (status.state === "unlocked") {
      agent.setMenuState(true).catch(() => {});
      await vaultState.loadLogins();
      if (vaultState.status.state === "locked") {
        hasCheckedAgent = true;
        await goto("/login");
        return;
      }
    }
    hasCheckedAgent = true;
  }

  async function handleSync() {
    await vaultState.sync();
    if (vaultState.status.state === "locked") {
      await goto("/login");
    }
  }

  async function handleSelectItem(name: string) {
    showDetailPassword = false;
    await vaultState.selectLogin(name);
    if (vaultState.status.state === "locked") {
      await goto("/login");
    }
  }

  async function handleCopy(text: string, fieldId: string) {
    if (!text) return;
    try {
      await agent.copyToClipboard(text);
      copiedField = fieldId;
      setTimeout(() => {
        if (copiedField === fieldId) copiedField = null;
      }, 2000);
    } catch (e) {
      console.warn("Error al copiar al portapapeles:", e);
    }
  }

  onMount(() => {
    initVault();
  });
</script>

<h1 class="sr-only">Bóveda de credenciales</h1>

<div class="vault-container">
  <!-- 1. Sidebar (Izquierda) -->
  <aside class="vault-sidebar">
    <nav class="sidebar-nav" aria-label="Secciones de la bóveda">
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

      <a href="/ssh" class="nav-item">
        <Terminal size={18} />
        <span>Claves SSH</span>
      </a>

      <a href="/settings" class="nav-item">
        <Settings size={18} />
        <span>Ajustes</span>
      </a>
    </nav>
  </aside>

  <!-- 2. Lista de elementos (Centro) -->
  <section class="vault-list-section" aria-label="Lista de accesos">
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
        disabled={syncing || isDisconnected}
        title="Sincronizar con el servidor Bitwarden"
        aria-label="Sincronizar bóveda"
      >
        <span class="icon-wrap" class:spin={syncing}>
          <RefreshCw size={15} />
        </span>
        <span>{syncing ? "Sincronizando..." : "Sincronizar"}</span>
      </button>
    </div>

    <div class="list-content">
      {#if !hasCheckedAgent || (syncing && vaultState.logins.length === 0)}
        <!-- Skeletons mientras carga (mínimo 250ms) -->
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
      {:else if isDisconnected}
        <div class="empty-state error-state" role="alert">
          <WifiOff size={32} class="empty-icon" color="var(--color-warning)" />
          <p class="empty-title">Agente desconectado</p>
          <p class="empty-subtitle">No se encontró <code>sw-agent</code>. Inicia el demonio y reintenta.</p>
          <button type="button" class="nav-item active retry-btn" onclick={initVault}>
            Reintentar conexión
          </button>
        </div>
      {:else if errorMsg}
        <div class="empty-state error-state" role="alert">
          <AlertCircle size={32} class="empty-icon" color="var(--color-danger)" />
          <p class="empty-title">{errorMsg}</p>
          <button
            type="button"
            class="nav-item active retry-btn"
            onclick={() => vaultState.loadLogins()}
          >
            Reintentar
          </button>
        </div>
      {:else if vaultState.logins.length === 0}
        <!-- Estado vacío: Sin logins -->
        <div class="empty-state">
          <KeyRound size={36} class="empty-icon" />
          <p class="empty-title">No hay logins en la bóveda. Sincroniza primero con el servidor.</p>
          <button
            type="button"
            class="sync-action-btn"
            onclick={handleSync}
            disabled={syncing}
          >
            <span class="icon-wrap" class:spin={syncing}>
              <RefreshCw size={15} />
            </span>
            <span>{syncing ? "Sincronizando..." : "Sincronizar con el Servidor"}</span>
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
              class:selected={vaultState.selectedLogin?.name === login.name}
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
  <section class="vault-details-section" aria-label="Detalles de credencial">
    {#if vaultState.selectedLogin}
      <div class="detail-container">
        <div class="detail-header">
          <div class="detail-avatar">
            <KeyRound size={24} color="var(--color-primary)" />
          </div>
          <div class="detail-header-text">
            <h2>{vaultState.selectedLogin.name}</h2>
            <span class="detail-tag">Login</span>
          </div>
        </div>

        <div class="detail-fields-list">
          {#if vaultState.selectedLogin.username}
            <div class="detail-field">
              <span class="field-label">Nombre de usuario</span>
              <div class="field-box">
                <span class="field-value">{vaultState.selectedLogin.username}</span>
                <button
                  type="button"
                  class="field-btn"
                  onclick={() => handleCopy(vaultState.selectedLogin!.username, "username")}
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

          {#if vaultState.selectedLogin.password}
            <div class="detail-field">
              <span class="field-label">Contraseña</span>
              <div class="field-box">
                <span class="field-value font-mono">
                  {showDetailPassword ? vaultState.selectedLogin.password : "••••••••••••••••"}
                </span>
                <div class="field-actions">
                  <button
                    type="button"
                    class="field-btn"
                    onclick={() => (showDetailPassword = !showDetailPassword)}
                    aria-pressed={showDetailPassword}
                    title={showDetailPassword ? "Ocultar contraseña" : "Ver contraseña"}
                    aria-label="Mostrar contraseña"
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
                    onclick={() => handleCopy(vaultState.selectedLogin!.password, "password")}
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

          {#if vaultState.selectedLogin.totp}
            <div class="detail-field">
              <span class="field-label">Código TOTP (2FA)</span>
              <div class="field-box">
                <span class="field-value font-mono">{vaultState.selectedLogin.totp}</span>
                <button
                  type="button"
                  class="field-btn"
                  onclick={() => handleCopy(vaultState.selectedLogin!.totp, "totp")}
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
        <h2>Detalles del Acceso</h2>
        <p>Selecciona un login de la lista para ver su usuario, contraseña y opciones de seguridad.</p>
      </div>
    {/if}
  </section>
</div>

<style>
  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip-path: inset(50%);
    white-space: nowrap;
    border: 0;
  }

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
    text-decoration: none;
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
    font-size: var(--font-size-sm);
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

  .detail-header-text h2 {
    margin: 0;
    font-size: var(--font-size-lg);
    color: var(--color-text);
  }

  .detail-tag {
    font-size: var(--font-size-sm);
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

  .details-placeholder h2 {
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
