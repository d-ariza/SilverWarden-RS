<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";
  import { Lock, Eye, EyeOff, Fingerprint, RefreshCw } from "lucide-svelte";
  import Modal from "$lib/components/ui/Modal.svelte";

  let agentStatus = $state("Cargando estado del agente...");
  let isRefreshing = $state(false);
  let isUnlocking = $state(false);
  let unlockProgress = $state(0);
  let showPin = $state(false);
  let pin = $state("");
  let errorMsg = $state("");

  const unlockPhases = [
    "Derivando clave maestra (Argon2i)...",
    "Verificando integridad de la clave...",
    "Descifrando bóveda y sesiones...",
  ];

  async function checkStatus() {
    isRefreshing = true;
    try {
      const [res] = await Promise.all([
        invoke<{ text?: string; error?: string }>("get_agent_status"),
        new Promise((r) => setTimeout(r, 300)),
      ]);
      agentStatus = res.text || res.error || "Agente conectado";
    } catch (e) {
      agentStatus = `Error al consultar agente: ${e}`;
    } finally {
      isRefreshing = false;
    }
  }

  async function handleUnlock() {
    if (!pin.trim()) {
      errorMsg = "Por favor introduce tu PIN.";
      return;
    }

    isUnlocking = true;
    unlockProgress = 0;
    errorMsg = "";

    const timer = setInterval(() => {
      unlockProgress = Math.min(
        unlockProgress + Math.floor(Math.random() * 5) + 3,
        95
      );
    }, 150);

    try {
      const result = await invoke<string>("unlock_vault", { pin });
      if (result === "unlocked") {
        clearInterval(timer);
        unlockProgress = 100;
        pin = "";
        try {
          await invoke("set_menu_state", { isLoggedIn: true });
        } catch (e) {
          console.warn("No se pudo actualizar el menú:", e);
        }
        try {
          await invoke("sync_vault");
        } catch (e) {
          console.warn("Error en sync tras desbloqueo:", e);
        }
        await new Promise((r) => setTimeout(r, 300));
        isUnlocking = false;
        await goto("/vault");
      }
    } catch (err) {
      clearInterval(timer);
      errorMsg = typeof err === "string" ? err : String(err);
      isUnlocking = false;
    } finally {
      clearInterval(timer);
    }
  }

  onMount(() => {
    checkStatus();
    invoke("set_menu_state", { isLoggedIn: false }).catch(() => {});
  });
</script>

<div class="login-container">
  <div class="card">
    <div class="card-header">
      <div class="title-row">
        <Lock size={24} color="var(--color-primary)" />
        <h2>Bóveda SilverWarden</h2>
      </div>
      <p class="subtitle">Desbloqueo seguro y gestión de sesión</p>
    </div>

    <div class="status-card">
      <span class="status-dot"></span>
      <span class="status-text">{agentStatus}</span>
      <button
        type="button"
        class="refresh-btn"
        onclick={checkStatus}
        disabled={isRefreshing || isUnlocking}
        title="Refrescar Estado"
        aria-label="Refrescar estado"
      >
        <span class="icon-wrap" class:spin={isRefreshing}>
          <RefreshCw size={16} />
        </span>
      </button>
    </div>

    <form class="login-form" onsubmit={(e) => { e.preventDefault(); handleUnlock(); }}>
      <div class="input-group">
        <label for="pin-input">PIN de Desbloqueo</label>
        <div class="input-wrapper">
          <input
            id="pin-input"
            type={showPin ? "text" : "password"}
            bind:value={pin}
            oninput={() => { errorMsg = ""; }}
            class:input-error={errorMsg.length > 0}
            placeholder="Introduce tu PIN maestro..."
            autocomplete="current-password"
            disabled={isUnlocking}
          />
          <button
            type="button"
            class="toggle-pin-btn"
            onclick={() => (showPin = !showPin)}
            aria-label={showPin ? "Ocultar PIN" : "Mostrar PIN"}
            title={showPin ? "Ocultar PIN" : "Mostrar PIN"}
            disabled={isUnlocking}
          >
            {#if showPin}
              <EyeOff size={18} />
            {:else}
              <Eye size={18} />
            {/if}
          </button>
        </div>
        {#if errorMsg}
          <p class="error-message">{errorMsg}</p>
        {/if}
      </div>

      <div class="form-actions">
        {#if false}
          <button
            type="button"
            class="btn btn-secondary"
            title="Desbloquear con biometría Polkit"
            disabled={isUnlocking}
          >
            <Fingerprint size={18} />
            <span>Biometría</span>
          </button>
        {/if}
        <button type="submit" class="btn btn-primary" disabled={isUnlocking}>
          {#if isUnlocking}
            <span class="spinner"></span>
            <span>Desbloqueando...</span>
          {:else}
            <span>Desbloquear</span>
          {/if}
        </button>
      </div>
    </form>

    <div class="card-footer-link">
      <a href="/setup" class="link-muted">Configurar cuenta nueva o cambiar servidor</a>
    </div>
  </div>
</div>

<Modal
  open={isUnlocking}
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
    max-width: 480px;
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .card-header {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .title-row {
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }

  .title-row h2 {
    margin: 0;
    font-size: var(--font-size-xl);
    color: var(--color-text);
  }

  .subtitle {
    margin: 0;
    font-size: var(--font-size-sm);
    color: var(--color-text-muted);
  }

  .status-card {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-2) var(--space-3);
    background-color: var(--color-bg);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-sm);
    font-size: var(--font-size-sm);
    color: var(--color-text);
    line-height: 1.4;
  }

  .status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background-color: var(--color-primary);
    flex-shrink: 0;
  }

  .status-text {
    flex: 1;
    word-break: break-word;
  }

  .refresh-btn {
    background: transparent;
    border: none;
    color: var(--color-text-muted);
    cursor: pointer;
    padding: var(--space-1);
    min-width: 36px;
    min-height: 36px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border-radius: var(--radius-md);
    transition: all var(--transition-fast);
  }

  .refresh-btn:hover:not(:disabled) {
    color: var(--color-primary);
    background-color: var(--color-skeleton);
  }

  .refresh-btn:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: 2px;
  }

  .refresh-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
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

  .login-form {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    margin-top: var(--space-2);
  }

  .input-group {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .input-group label {
    font-size: var(--font-size-sm);
    color: var(--color-text);
    font-weight: 500;
  }

  .input-wrapper {
    position: relative;
    display: flex;
    align-items: center;
    width: 100%;
  }

  .input-wrapper input {
    width: 100%;
    box-sizing: border-box;
    padding: var(--space-2) var(--space-8) var(--space-2) var(--space-3);
    min-height: 40px;
    background-color: var(--color-bg);
    color: var(--color-text);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    font-size: var(--font-size-base);
    font-family: inherit;
    transition: border-color var(--transition-fast);
  }

  .input-wrapper input:focus-visible,
  .input-wrapper input:focus {
    outline: 2px solid var(--color-primary);
    outline-offset: 1px;
    border-color: var(--color-primary);
  }

  .input-wrapper input.input-error {
    border-color: var(--color-danger);
  }

  .input-wrapper input.input-error:focus-visible,
  .input-wrapper input.input-error:focus {
    outline-color: var(--color-danger);
    border-color: var(--color-danger);
  }

  .error-message {
    margin: var(--space-1) 0 0 0;
    font-size: var(--font-size-sm);
    color: var(--color-danger);
  }

  .toggle-pin-btn {
    position: absolute;
    right: var(--space-2);
    top: 50%;
    transform: translateY(-50%);
    background: transparent;
    border: none;
    color: var(--color-text-muted);
    cursor: pointer;
    padding: var(--space-1);
    min-width: 32px;
    min-height: 32px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border-radius: var(--radius-md);
    transition: color var(--transition-fast);
  }

  .toggle-pin-btn:hover:not(:disabled) {
    color: var(--color-text);
  }

  .toggle-pin-btn:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: 2px;
  }

  .form-actions {
    display: flex;
    gap: var(--space-2);
    justify-content: flex-end;
    margin-top: var(--space-2);
  }

  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: var(--space-2);
    padding: var(--space-2) var(--space-4);
    min-height: 40px;
    border-radius: var(--radius-md);
    font-size: var(--font-size-sm);
    font-family: inherit;
    font-weight: 500;
    cursor: pointer;
    transition: all var(--transition-fast);
  }

  .btn:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: 2px;
  }

  .btn-primary {
    width: 100%;
    min-width: 140px;
    background-color: var(--color-primary);
    color: var(--color-primary-text);
    border: 1px solid var(--color-primary);
  }

  .btn-primary:hover:not(:disabled) {
    background-color: var(--color-primary-hover);
    border-color: var(--color-primary-hover);
  }

  :global(.btn-secondary) {
    min-width: 120px;
    background-color: var(--color-bg);
    color: var(--color-text);
    border: 1px solid var(--color-border);
  }

  :global(.btn-secondary:hover:not(:disabled)) {
    background-color: var(--color-skeleton);
  }

  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .spinner {
    width: 14px;
    height: 14px;
    border: 2px solid var(--color-primary-text);
    border-top-color: transparent;
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
    display: inline-block;
  }

  .card-footer-link {
    text-align: center;
    padding-top: var(--space-2);
    border-top: 1px solid var(--color-border);
  }

  .link-muted {
    font-size: var(--font-size-sm);
    color: var(--color-text-muted);
    text-decoration: none;
    transition: color var(--transition-fast);
  }

  .link-muted:hover {
    color: var(--color-primary);
    text-decoration: underline;
  }
</style>

