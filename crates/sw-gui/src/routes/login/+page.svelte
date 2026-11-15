<script lang="ts">
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";
  import {
    Lock,
    Eye,
    EyeOff,
    Fingerprint,
    RefreshCw,
    WifiOff,
    AlertCircle,
    CheckCircle2,
  } from "lucide-svelte";
  import { agent } from "$lib/api/agent";
  import { vaultState } from "$lib/state/vault.svelte";
  import Modal from "$lib/components/ui/Modal.svelte";

  let isRefreshing = $state(false);
  let unlockProgress = $state(0);
  let showPin = $state(false);
  let pin = $state("");
  let validationError = $state("");
  let hasBiometrics = $state(false);

  const unlockPhases = [
    "Derivando clave maestra (Argon2i)...",
    "Verificando integridad de la clave...",
    "Descifrando bóveda y sesiones...",
  ];

  let activeError = $derived(
    validationError ||
      (vaultState.status.state === "error" ? vaultState.status.message : "")
  );

  let agentStatusText = $derived.by(() => {
    switch (vaultState.status.state) {
      case "disconnected":
        return "Agente desconectado";
      case "needs_setup":
        return "Configuración inicial requerida";
      case "logged_out":
        return "Sesión de Bitwarden cerrada";
      case "locked":
        return "Agente conectado · Bóveda bloqueada";
      case "unlocking":
        return "Desbloqueando bóveda...";
      case "unlocked":
      case "syncing":
        return "Agente conectado · Bóveda desbloqueada";
      case "error":
        return `Error del agente: ${vaultState.status.message}`;
    }
  });

  async function checkStatus() {
    isRefreshing = true;
    validationError = "";
    try {
      const [status] = await Promise.all([
        vaultState.refreshStatus(),
        new Promise((r) => setTimeout(r, 250)),
      ]);
      if (status.state === "unlocked" || status.state === "syncing") {
        await goto("/vault");
      }
    } finally {
      isRefreshing = false;
    }
  }

  async function handleUnlock() {
    if (!pin.trim()) {
      validationError = "Por favor introduce tu PIN.";
      return;
    }

    validationError = "";
    if (vaultState.status.state === "disconnected") {
      const current = await vaultState.refreshStatus();
      if (current.state === "disconnected") {
        return;
      }
    }

    unlockProgress = 0;
    const timer = setInterval(() => {
      unlockProgress = Math.min(
        unlockProgress + Math.floor(Math.random() * 5) + 3,
        95
      );
    }, 150);

    try {
      const unlocked = await vaultState.unlock(pin);
      if (unlocked) {
        clearInterval(timer);
        unlockProgress = 100;
        pin = "";
        await new Promise((r) => setTimeout(r, 200));
        await goto("/vault");
      }
    } finally {
      clearInterval(timer);
    }
  }

  onMount(() => {
    checkStatus();
    agent.setMenuState(false).catch(() => {});
  });
</script>

<div class="login-container">
  <div class="card">
    <div class="card-header">
      <div class="title-row">
        <Lock size={24} color="var(--color-primary)" />
        <h1>Bóveda SilverWarden</h1>
      </div>
      <p class="subtitle">Desbloqueo seguro y gestión de sesión</p>
    </div>

    <div
      class="status-card"
      class:is-disconnected={vaultState.status.state === "disconnected"}
      class:is-error={vaultState.status.state === "error"}
    >
      <span class="status-icon" aria-hidden="true">
        {#if vaultState.status.state === "disconnected"}
          <WifiOff size={16} color="var(--color-warning)" />
        {:else if vaultState.status.state === "error"}
          <AlertCircle size={16} color="var(--color-danger)" />
        {:else}
          <CheckCircle2 size={16} color="var(--color-success)" />
        {/if}
      </span>
      <span class="status-text">{agentStatusText}</span>
      <button
        type="button"
        class="refresh-btn"
        onclick={checkStatus}
        disabled={isRefreshing || vaultState.status.state === "unlocking"}
        title="Refrescar Estado"
        aria-label="Refrescar estado del agente"
      >
        <span class="icon-wrap" class:spin={isRefreshing}>
          <RefreshCw size={16} />
        </span>
      </button>
    </div>

    {#if vaultState.status.state === "disconnected"}
      <div class="state-banner warning" role="alert">
        <WifiOff size={18} color="var(--color-warning)" />
        <div>
          <strong>Sin conexión con el agente</strong>
          <p>El demonio <code>sw-agent</code> no responde. Inícialo y pulsa refrescar para desbloquear.</p>
        </div>
      </div>
    {:else if vaultState.status.state === "logged_out" || vaultState.status.state === "needs_setup"}
      <div class="state-banner info" role="status">
        <AlertCircle size={18} color="var(--color-primary)" />
        <div>
          <strong>Sesión no iniciada</strong>
          <p>
            Completa la configuración inicial en <a href="/setup">Configuración</a> o ajusta tu servidor en
            <a href="/settings">Ajustes</a>.
          </p>
        </div>
      </div>
    {/if}

    <form class="login-form" onsubmit={(e) => { e.preventDefault(); handleUnlock(); }}>
      <div class="input-group">
        <label for="pin-input">PIN de Desbloqueo</label>
        <div class="input-wrapper">
          <input
            id="pin-input"
            type={showPin ? "text" : "password"}
            bind:value={pin}
            oninput={() => {
              validationError = "";
              vaultState.clearErrorTo("locked");
            }}
            class:input-error={activeError.length > 0}
            aria-invalid={activeError.length > 0 ? "true" : undefined}
            aria-describedby={activeError.length > 0 ? "pin-error" : undefined}
            placeholder="Introduce tu PIN maestro..."
            autocomplete="current-password"
            disabled={vaultState.status.state === "unlocking"}
          />
          <button
            type="button"
            class="toggle-pin-btn"
            onclick={() => (showPin = !showPin)}
            aria-pressed={showPin}
            aria-label="Mostrar PIN"
            title={showPin ? "Ocultar PIN" : "Mostrar PIN"}
            disabled={vaultState.status.state === "unlocking"}
          >
            {#if showPin}
              <EyeOff size={18} />
            {:else}
              <Eye size={18} />
            {/if}
          </button>
        </div>
        {#if activeError}
          <p id="pin-error" class="error-message" role="alert">{activeError}</p>
        {/if}
      </div>

      <div class="form-actions">
        {#if hasBiometrics}
          <button
            type="button"
            class="btn btn-secondary"
            title="Desbloquear con biometría Polkit"
            disabled={vaultState.status.state === "unlocking"}
          >
            <Fingerprint size={18} />
            <span>Biometría</span>
          </button>
        {/if}
        <button
          type="submit"
          class="btn btn-primary"
          disabled={vaultState.status.state === "unlocking"}
        >
          {#if vaultState.status.state === "unlocking"}
            <span class="spinner"></span>
            <span>Desbloqueando...</span>
          {:else}
            <span>Desbloquear</span>
          {/if}
        </button>
      </div>
    </form>

    <div class="footer-links">
      <button
        type="button"
        class="link-button"
        onclick={() => goto("/setup")}
        disabled={vaultState.status.state === "unlocking"}
      >
        ¿Primera vez o cambiar cuenta? Ir a Configuración
      </button>
    </div>
  </div>
</div>

<Modal
  open={vaultState.status.state === "unlocking"}
  title="Desbloqueando Bóveda"
  phases={unlockPhases}
  progress={unlockProgress}
/>

<style>
  .login-container {
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 65vh;
  }

  .card {
    background-color: var(--color-bg-alt);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-md);
    padding: var(--space-6);
    width: 100%;
    max-width: 440px;
    transition: background-color var(--transition-fast), border-color var(--transition-fast);
  }

  .card-header {
    margin-bottom: var(--space-4);
  }

  .title-row {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin-bottom: var(--space-1);
  }

  .title-row h1 {
    margin: 0;
    font-size: var(--font-size-xl);
    color: var(--color-text);
  }

  .subtitle {
    margin: 0;
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }

  .status-card {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-3);
    background-color: var(--color-bg);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    margin-bottom: var(--space-4);
  }

  .status-card.is-disconnected {
    border-color: var(--color-warning);
  }

  .status-card.is-error {
    border-color: var(--color-danger);
  }

  .status-icon {
    display: inline-flex;
    align-items: center;
    flex-shrink: 0;
  }

  .status-text {
    font-size: var(--font-size-sm);
    color: var(--color-text);
    flex: 1;
    font-weight: 500;
  }

  .state-banner {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    padding: var(--space-3);
    border-radius: var(--radius-md);
    border: 1px solid var(--color-border);
    background-color: var(--color-bg);
    margin-bottom: var(--space-4);
    font-size: var(--font-size-sm);
  }

  .state-banner.warning {
    border-color: var(--color-warning);
  }

  .state-banner.info {
    border-color: var(--color-primary);
  }

  .state-banner p {
    margin: var(--space-1) 0 0 0;
    color: var(--color-text-muted);
    line-height: 1.4;
  }

  .state-banner a {
    color: var(--color-primary);
    font-weight: 500;
  }

  .refresh-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 36px;
    height: 36px;
    border-radius: var(--radius-md);
    border: 1px solid var(--color-border);
    background: var(--color-bg-alt);
    color: var(--color-text-muted);
    cursor: pointer;
    transition: background-color var(--transition-fast), color var(--transition-fast);
  }

  .refresh-btn:hover:not(:disabled) {
    background-color: var(--color-skeleton);
    color: var(--color-text);
  }

  .refresh-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .icon-wrap {
    display: inline-flex;
    align-items: center;
  }

  :global(.spin) {
    animation: spin 1s linear infinite;
  }

  .login-form {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .input-group {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .input-group label {
    font-size: var(--font-size-sm);
    font-weight: 500;
    color: var(--color-text);
  }

  .input-wrapper {
    position: relative;
    display: flex;
    align-items: center;
  }

  .input-wrapper input {
    width: 100%;
    min-height: 44px;
    padding: var(--space-2) var(--space-6) var(--space-2) var(--space-3);
    padding-right: 44px;
    border-radius: var(--radius-md);
    border: 1px solid var(--color-border);
    background-color: var(--color-bg);
    color: var(--color-text);
    font-family: inherit;
    font-size: var(--font-size-base);
    box-sizing: border-box;
    transition: border-color var(--transition-fast);
  }

  .input-wrapper input:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: 2px;
    border-color: var(--color-primary);
  }

  .input-wrapper input.input-error {
    border-color: var(--color-danger);
  }

  .input-wrapper input.input-error:focus-visible {
    outline-color: var(--color-danger);
    border-color: var(--color-danger);
  }

  .error-message {
    margin: var(--space-1) 0 0 0;
    font-size: var(--font-size-sm);
    color: var(--color-danger);
    font-weight: 500;
  }

  .toggle-pin-btn {
    position: absolute;
    right: var(--space-1);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 36px;
    min-height: 36px;
    border: none;
    background: transparent;
    color: var(--color-text-muted);
    cursor: pointer;
    padding: var(--space-1);
    border-radius: var(--radius-sm);
  }

  .toggle-pin-btn:hover {
    color: var(--color-text);
  }

  .form-actions {
    display: flex;
    gap: var(--space-3);
    margin-top: var(--space-2);
  }

  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: var(--space-2);
    padding: var(--space-2) var(--space-4);
    border-radius: var(--radius-md);
    font-family: inherit;
    font-size: var(--font-size-base);
    font-weight: 500;
    cursor: pointer;
    border: 1px solid transparent;
    transition: background-color var(--transition-fast), opacity var(--transition-fast);
    min-height: 44px;
  }

  .btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .btn-primary {
    flex: 1;
    background-color: var(--color-primary);
    color: var(--color-primary-text);
  }

  .btn-primary:hover:not(:disabled) {
    background-color: var(--color-primary-hover);
  }

  .btn-secondary {
    background-color: var(--color-bg);
    color: var(--color-text);
    border-color: var(--color-border);
  }

  .btn-secondary:hover:not(:disabled) {
    background-color: var(--color-skeleton);
  }

  .spinner {
    width: 16px;
    height: 16px;
    border: 2px solid transparent;
    border-top-color: currentColor;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  .footer-links {
    margin-top: var(--space-4);
    padding-top: var(--space-4);
    border-top: 1px solid var(--color-border);
    text-align: center;
  }

  .link-button {
    background: none;
    border: none;
    color: var(--color-primary);
    font-size: var(--font-size-sm);
    font-family: inherit;
    cursor: pointer;
    padding: var(--space-2);
    min-height: 36px;
    text-decoration: underline;
    text-underline-offset: 3px;
  }

  .link-button:hover:not(:disabled) {
    color: var(--color-primary-hover);
  }

  .link-button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
</style>
