<script lang="ts">
  import { onMount } from "svelte";
  import {
    Settings,
    Server,
    KeyRound,
    Eye,
    EyeOff,
    Check,
    WifiOff,
    AlertCircle,
    RefreshCw,
    Info,
  } from "lucide-svelte";
  import { agent } from "$lib/api/agent";
  import type { ConfigView } from "$lib/types/generated/ConfigView";
  import { vaultState } from "$lib/state/vault.svelte";
  import { isDisconnectedError } from "$lib/state/transitions";

  let loading = $state(true);
  let disconnected = $state(false);
  let loadError = $state<string | null>(null);
  let hasPin = $state(false);

  let apiUrl = $state("");
  let identityUrl = $state("");
  let notificationsUrl = $state("");
  let dangerAcceptInvalidCerts = $state(false);

  let savingConfig = $state(false);
  let configMessage = $state("");
  let configError = $state("");

  let oldPin = $state("");
  let newPin = $state("");
  let confirmPin = $state("");
  let showPins = $state(false);
  let savingPin = $state(false);
  let pinMessage = $state("");
  let pinError = $state("");

  let hasEmptyUrls = $derived(
    !apiUrl.trim() && !identityUrl.trim() && !notificationsUrl.trim()
  );

  function messageFromError(err: unknown): string {
    return err instanceof Error ? err.message : typeof err === "string" ? err : String(err);
  }

  async function loadSettingsView() {
    loading = true;
    disconnected = false;
    loadError = null;

    const status = await vaultState.refreshStatus();
    if (status.state === "disconnected") {
      disconnected = true;
      loading = false;
      return;
    }
    if (status.state === "error") {
      loadError = status.message;
      loading = false;
      return;
    }

    try {
      const [[agentStatus, cfg]] = await Promise.all([
        Promise.all([agent.getStatus(), agent.getConfig()]),
        new Promise((r) => setTimeout(r, 250)),
      ]);
      hasPin = agentStatus.has_pin;
      apiUrl = cfg.api_url;
      identityUrl = cfg.identity_url;
      notificationsUrl = cfg.notifications_url;
      dangerAcceptInvalidCerts = cfg.danger_accept_invalid_certs;
    } catch (err) {
      const msg = messageFromError(err);
      if (isDisconnectedError(msg)) {
        disconnected = true;
      } else {
        loadError = msg;
      }
    } finally {
      loading = false;
    }
  }

  function fillOfficialDefaults() {
    apiUrl = "https://api.bitwarden.com";
    identityUrl = "https://identity.bitwarden.com";
    notificationsUrl = "https://notifications.bitwarden.com";
    configMessage = "";
    configError = "";
  }

  async function handleSaveConfig() {
    savingConfig = true;
    configMessage = "";
    configError = "";
    const payload: ConfigView = {
      api_url: apiUrl.trim(),
      identity_url: identityUrl.trim(),
      notifications_url: notificationsUrl.trim(),
      danger_accept_invalid_certs: dangerAcceptInvalidCerts,
    };

    try {
      const saved = await agent.setConfig(payload);
      apiUrl = saved.api_url;
      identityUrl = saved.identity_url;
      notificationsUrl = saved.notifications_url;
      dangerAcceptInvalidCerts = saved.danger_accept_invalid_certs;
      configMessage = "Configuración del servidor guardada correctamente.";
    } catch (err) {
      const msg = messageFromError(err);
      if (isDisconnectedError(msg)) {
        disconnected = true;
      } else {
        configError = msg;
      }
    } finally {
      savingConfig = false;
    }
  }

  async function handleSavePin() {
    pinMessage = "";
    pinError = "";

    if (hasPin && !oldPin) {
      pinError = "Introduce tu PIN actual para cambiarlo.";
      return;
    }
    if (!newPin || newPin.length < 4) {
      pinError = "El nuevo PIN debe tener al menos 4 caracteres.";
      return;
    }
    if (newPin !== confirmPin) {
      pinError = "El nuevo PIN y su confirmación no coinciden.";
      return;
    }

    savingPin = true;
    try {
      const result = hasPin
        ? await agent.pinUpdate(oldPin, newPin)
        : await agent.pinSet(newPin);
      if (result.updated) {
        hasPin = true;
        oldPin = "";
        newPin = "";
        confirmPin = "";
        pinMessage = "PIN actualizado correctamente en el agente.";
      } else {
        pinError = `No se pudo actualizar el PIN (${result.status}).`;
      }
    } catch (err) {
      const msg = messageFromError(err);
      if (isDisconnectedError(msg)) {
        disconnected = true;
      } else {
        pinError = msg;
      }
    } finally {
      savingPin = false;
    }
  }

  onMount(() => {
    loadSettingsView();
  });
</script>

<div class="settings-page">
  <header class="page-header">
    <div>
      <div class="title-row">
        <Settings size={24} color="var(--color-primary)" />
        <h1>Ajustes y Seguridad</h1>
      </div>
      <p class="subtitle">Configura las URLs de tu servidor Bitwarden y gestiona tu PIN maestro</p>
    </div>

    <button
      type="button"
      class="btn btn-secondary"
      onclick={loadSettingsView}
      disabled={loading}
      aria-label="Recargar configuración"
    >
      <span class="icon-wrap" class:spin={loading}>
        <RefreshCw size={16} />
      </span>
      <span>Recargar</span>
    </button>
  </header>

  {#if loading}
    <div class="settings-grid" aria-busy="true" aria-label="Cargando ajustes">
      <div class="panel skeleton-card">
        <div class="skeleton-line skeleton-title"></div>
        <div class="skeleton-line skeleton-field"></div>
        <div class="skeleton-line skeleton-field"></div>
        <div class="skeleton-line skeleton-field"></div>
      </div>
      <div class="panel skeleton-card">
        <div class="skeleton-line skeleton-title"></div>
        <div class="skeleton-line skeleton-field"></div>
        <div class="skeleton-line skeleton-field"></div>
      </div>
    </div>
  {:else if disconnected}
    <section class="state-card warning" role="alert">
      <WifiOff size={32} color="var(--color-warning)" />
      <h2>Agente desconectado</h2>
      <p>No se pudo contactar con <code>sw-agent</code>. Inicia el demonio para editar la configuración.</p>
      <button type="button" class="btn btn-primary" onclick={loadSettingsView}>
        Reintentar conexión
      </button>
    </section>
  {:else if loadError}
    <section class="state-card danger" role="alert">
      <AlertCircle size={32} color="var(--color-danger)" />
      <h2>Error al cargar ajustes</h2>
      <p>{loadError}</p>
      <button type="button" class="btn btn-primary" onclick={loadSettingsView}>
        Reintentar
      </button>
    </section>
  {:else}
    <div class="settings-grid">
      <section class="panel" aria-labelledby="server-config-heading">
        <div class="panel-heading">
          <Server size={18} color="var(--color-primary)" />
          <h2 id="server-config-heading">Servidor Bitwarden / Vaultwarden</h2>
        </div>

        {#if hasEmptyUrls}
          <div class="info-banner" role="status">
            <Info size={18} color="var(--color-primary)" />
            <div class="info-copy">
              <span>Sin URLs personalizadas; se usarán los valores por defecto de Bitwarden.</span>
              <button type="button" class="inline-link-btn" onclick={fillOfficialDefaults}>
                Rellenar valores oficiales
              </button>
            </div>
          </div>
        {/if}

        {#if configMessage}
          <div class="banner success" role="status" aria-live="polite">
            <Check size={18} color="var(--color-success)" />
            <span>{configMessage}</span>
          </div>
        {/if}

        {#if configError}
          <div class="banner danger" role="alert">
            <AlertCircle size={18} color="var(--color-danger)" />
            <span>{configError}</span>
          </div>
        {/if}

        <form class="stack-form" onsubmit={(e) => { e.preventDefault(); handleSaveConfig(); }}>
          <div class="field-group">
            <label for="api-url">URL de API (`api_url`)</label>
            <input
              id="api-url"
              type="url"
              bind:value={apiUrl}
              placeholder="https://api.bitwarden.com"
              disabled={savingConfig}
            />
          </div>

          <div class="field-group">
            <label for="identity-url">URL de Identidad (`identity_url`)</label>
            <input
              id="identity-url"
              type="url"
              bind:value={identityUrl}
              placeholder="https://identity.bitwarden.com"
              disabled={savingConfig}
            />
          </div>

          <div class="field-group">
            <label for="notifications-url">URL de Notificaciones (`notifications_url`)</label>
            <input
              id="notifications-url"
              type="url"
              bind:value={notificationsUrl}
              placeholder="https://notifications.bitwarden.com"
              disabled={savingConfig}
            />
          </div>

          <label class="checkbox-row" for="accept-invalid-certs">
            <input
              id="accept-invalid-certs"
              type="checkbox"
              bind:checked={dangerAcceptInvalidCerts}
              disabled={savingConfig}
            />
            <span>
              Aceptar certificados TLS inválidos o autofirmados (solo para entornos locales)
            </span>
          </label>

          <button type="submit" class="btn btn-primary" disabled={savingConfig}>
            {savingConfig ? "Guardando..." : "Guardar configuración"}
          </button>
        </form>
      </section>

      <section class="panel" aria-labelledby="pin-config-heading">
        <div class="panel-heading-between">
          <div class="panel-heading">
            <KeyRound size={18} color="var(--color-primary)" />
            <h2 id="pin-config-heading">{hasPin ? "Cambiar PIN maestro" : "Configurar PIN maestro"}</h2>
          </div>

          <button
            type="button"
            class="btn btn-secondary btn-compact"
            aria-pressed={showPins}
            onclick={() => (showPins = !showPins)}
            aria-label="Mostrar campos de PIN"
          >
            {#if showPins}
              <EyeOff size={16} />
              <span>Ocultar</span>
            {:else}
              <Eye size={16} />
              <span>Mostrar</span>
            {/if}
          </button>
        </div>

        {#if pinMessage}
          <div class="banner success" role="status" aria-live="polite">
            <Check size={18} color="var(--color-success)" />
            <span>{pinMessage}</span>
          </div>
        {/if}

        {#if pinError}
          <div class="banner danger" role="alert">
            <AlertCircle size={18} color="var(--color-danger)" />
            <span>{pinError}</span>
          </div>
        {/if}

        <form class="stack-form" onsubmit={(e) => { e.preventDefault(); handleSavePin(); }}>
          {#if hasPin}
            <div class="field-group">
              <label for="old-pin">PIN actual</label>
              <input
                id="old-pin"
                type={showPins ? "text" : "password"}
                bind:value={oldPin}
                autocomplete="current-password"
                required
                disabled={savingPin}
              />
            </div>
          {/if}

          <div class="field-group">
            <label for="new-pin">Nuevo PIN</label>
            <input
              id="new-pin"
              type={showPins ? "text" : "password"}
              bind:value={newPin}
              autocomplete="new-password"
              required
              minlength={4}
              disabled={savingPin}
            />
          </div>

          <div class="field-group">
            <label for="confirm-pin">Confirmar nuevo PIN</label>
            <input
              id="confirm-pin"
              type={showPins ? "text" : "password"}
              bind:value={confirmPin}
              autocomplete="new-password"
              required
              minlength={4}
              disabled={savingPin}
            />
          </div>

          <button type="submit" class="btn btn-primary" disabled={savingPin}>
            {savingPin
              ? "Actualizando..."
              : hasPin
                ? "Actualizar PIN"
                : "Establecer PIN"}
          </button>
        </form>
      </section>
    </div>
  {/if}
</div>

<style>
  .settings-page {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .page-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: var(--space-4);
    flex-wrap: wrap;
  }

  .title-row {
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }

  h1 {
    margin: 0;
    font-size: var(--font-size-xl);
    color: var(--color-text);
  }

  h2 {
    margin: 0;
    font-size: var(--font-size-lg);
    color: var(--color-text);
  }

  .subtitle {
    margin: var(--space-1) 0 0 0;
    font-size: var(--font-size-sm);
    color: var(--color-text-muted);
  }

  .settings-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    gap: var(--space-6);
    align-items: start;
  }

  .panel {
    background-color: var(--color-bg-alt);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-sm);
    padding: var(--space-6);
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .panel-heading {
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }

  .panel-heading-between {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-2);
    flex-wrap: wrap;
  }

  .info-banner,
  .banner {
    display: flex;
    align-items: flex-start;
    gap: var(--space-2);
    padding: var(--space-3);
    border-radius: var(--radius-md);
    border: 1px solid var(--color-border);
    background-color: var(--color-bg);
    font-size: var(--font-size-sm);
  }

  .banner.success {
    border-color: var(--color-success);
  }

  .banner.danger {
    border-color: var(--color-danger);
    color: var(--color-danger);
  }

  .info-copy {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: var(--space-1);
    color: var(--color-text-muted);
  }

  .inline-link-btn {
    background: none;
    border: none;
    padding: 0;
    color: var(--color-primary);
    font-family: inherit;
    font-size: var(--font-size-sm);
    font-weight: 500;
    text-decoration: underline;
    cursor: pointer;
  }

  .stack-form {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .field-group {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .field-group label {
    font-size: var(--font-size-sm);
    font-weight: 500;
    color: var(--color-text);
  }

  .field-group input {
    width: 100%;
    min-height: 44px;
    padding: var(--space-2) var(--space-3);
    border-radius: var(--radius-md);
    border: 1px solid var(--color-border);
    background-color: var(--color-bg);
    color: var(--color-text);
    font-family: inherit;
    font-size: var(--font-size-sm);
    box-sizing: border-box;
  }

  .checkbox-row {
    display: flex;
    align-items: flex-start;
    gap: var(--space-2);
    font-size: var(--font-size-sm);
    color: var(--color-text);
    cursor: pointer;
    line-height: 1.4;
  }

  .checkbox-row input[type="checkbox"] {
    width: 18px;
    height: 18px;
    margin-top: 2px;
    flex-shrink: 0;
  }

  .state-card {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    gap: var(--space-3);
    padding: var(--space-8) var(--space-4);
    border-radius: var(--radius-md);
    border: 1px solid var(--color-border);
    background-color: var(--color-bg-alt);
  }

  .state-card.warning {
    border-color: var(--color-warning);
  }

  .state-card.danger {
    border-color: var(--color-danger);
  }

  .state-card p {
    margin: 0;
    font-size: var(--font-size-sm);
    color: var(--color-text-muted);
    max-width: 420px;
  }

  .skeleton-card {
    gap: var(--space-3);
  }

  .skeleton-line {
    height: 18px;
    border-radius: var(--radius-sm);
    background-color: var(--color-skeleton);
  }

  .skeleton-title {
    width: 55%;
    height: 22px;
  }

  .skeleton-field {
    width: 100%;
    height: 40px;
  }

  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: var(--space-2);
    padding: var(--space-2) var(--space-4);
    min-height: 44px;
    border-radius: var(--radius-md);
    border: 1px solid transparent;
    font-family: inherit;
    font-size: var(--font-size-sm);
    font-weight: 500;
    cursor: pointer;
  }

  .btn-compact {
    min-height: 36px;
    padding: var(--space-1) var(--space-3);
  }

  .btn:disabled {
    opacity: 0.55;
    cursor: not-allowed;
  }

  .btn-primary {
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

  .icon-wrap {
    display: inline-flex;
    align-items: center;
  }
</style>
