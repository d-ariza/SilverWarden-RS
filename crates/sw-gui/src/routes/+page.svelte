<script lang="ts">
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";
  import { Shield, Loader2, WifiOff, AlertCircle, RefreshCw } from "lucide-svelte";
  import { vaultState } from "$lib/state/vault.svelte";

  let isProbing = $state(true);

  async function detectAgent() {
    isProbing = true;
    const status = await vaultState.refreshStatus();
    isProbing = false;

    if (status.state === "needs_setup") {
      await goto("/setup");
    } else if (status.state === "locked" || status.state === "logged_out") {
      await goto("/login");
    } else if (status.state === "unlocked" || status.state === "syncing") {
      await goto("/vault");
    }
  }

  onMount(() => {
    detectAgent();
  });
</script>

<div class="splash-container">
  <section class="splash-card" aria-label="Estado de conexión con SilverWarden">
    <Shield size={48} color="var(--color-primary)" />
    <h1>SilverWarden</h1>

    {#if isProbing}
      <div class="status-row" role="status" aria-live="polite">
        <Loader2 size={20} class="spin" color="var(--color-primary)" />
        <span>Conectando con el agente...</span>
      </div>
    {:else if vaultState.status.state === "disconnected"}
      <div class="alert-box warning" role="alert">
        <WifiOff size={20} color="var(--color-warning)" />
        <div>
          <strong>Agente desconectado</strong>
          <p>No se pudo contactar con el demonio <code>sw-agent</code>. Asegúrate de que está en ejecución.</p>
        </div>
      </div>
      <div class="actions-row">
        <button type="button" class="btn btn-primary" onclick={detectAgent}>
          <RefreshCw size={16} />
          <span>Reintentar conexión</span>
        </button>
        <a href="/login" class="btn btn-secondary">Ir a Desbloqueo</a>
      </div>
    {:else if vaultState.status.state === "error"}
      <div class="alert-box danger" role="alert">
        <AlertCircle size={20} color="var(--color-danger)" />
        <div>
          <strong>Error del agente</strong>
          <p>{vaultState.status.message}</p>
        </div>
      </div>
      <div class="actions-row">
        <button type="button" class="btn btn-primary" onclick={detectAgent}>
          <RefreshCw size={16} />
          <span>Reintentar</span>
        </button>
        <a href="/login" class="btn btn-secondary">Ir a Desbloqueo</a>
      </div>
    {/if}
  </section>
</div>

<style>
  .splash-container {
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 70vh;
    padding: var(--space-4);
  }

  .splash-card {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-4);
    max-width: 460px;
    width: 100%;
    text-align: center;
    color: var(--color-text);
  }

  h1 {
    margin: 0;
    font-size: var(--font-size-xl);
  }

  .status-row {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }

  .alert-box {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    text-align: left;
    padding: var(--space-4);
    border-radius: var(--radius-md);
    border: 1px solid var(--color-border);
    background-color: var(--color-bg-alt);
    width: 100%;
    box-sizing: border-box;
    font-size: var(--font-size-sm);
  }

  .alert-box.warning {
    border-color: var(--color-warning);
  }

  .alert-box.danger {
    border-color: var(--color-danger);
  }

  .alert-box p {
    margin: var(--space-1) 0 0 0;
    color: var(--color-text-muted);
    line-height: 1.4;
  }

  .actions-row {
    display: flex;
    gap: var(--space-3);
    flex-wrap: wrap;
    justify-content: center;
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
    font-weight: 500;
    font-family: inherit;
    text-decoration: none;
    cursor: pointer;
    border: 1px solid transparent;
  }

  .btn-primary {
    background-color: var(--color-primary);
    color: var(--color-primary-text);
  }

  .btn-primary:hover {
    background-color: var(--color-primary-hover);
  }

  .btn-secondary {
    background-color: var(--color-bg-alt);
    color: var(--color-text);
    border-color: var(--color-border);
  }

  .btn-secondary:hover {
    background-color: var(--color-skeleton);
  }
</style>
