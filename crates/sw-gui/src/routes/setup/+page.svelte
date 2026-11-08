<script lang="ts">
  import { goto } from "$app/navigation";
  import { Shield, Server, Mail, Lock, Eye, EyeOff, Info } from "lucide-svelte";

  let serverUrl = $state("https://vault.bitwarden.com");
  let email = $state("");
  let masterPassword = $state("");
  let showPassword = $state(false);
  let infoMessage = $state("");

  function handleSubmit() {
    infoMessage =
      "El inicio de sesión gráfico completo llegará con la v2. Por ahora, inicia sesión ejecutando 'silverwarden login' en tu terminal y luego regresa aquí.";
  }
</script>

<div class="setup-container">
  <div class="card">
    <div class="card-header">
      <div class="title-row">
        <Shield size={28} color="var(--color-primary)" />
        <h2>Bienvenido a SilverWarden</h2>
      </div>
      <p class="subtitle">Conecta tu cuenta de Bitwarden o Vaultwarden</p>
    </div>

    {#if infoMessage}
      <div class="info-banner" role="alert">
        <Info size={18} class="info-icon" />
        <div class="info-text">
          <p>{infoMessage}</p>
        </div>
      </div>
    {/if}

    <form class="setup-form" onsubmit={(e) => { e.preventDefault(); handleSubmit(); }}>
      <div class="input-group">
        <label for="server-url">Servidor Bitwarden / Vaultwarden</label>
        <div class="input-wrapper">
          <Server size={16} class="input-icon" />
          <input
            id="server-url"
            type="url"
            bind:value={serverUrl}
            placeholder="https://vault.bitwarden.com"
            required
          />
        </div>
      </div>

      <div class="input-group">
        <label for="email-input">Correo Electrónico</label>
        <div class="input-wrapper">
          <Mail size={16} class="input-icon" />
          <input
            id="email-input"
            type="email"
            bind:value={email}
            placeholder="usuario@ejemplo.com"
            autocomplete="email"
            required
          />
        </div>
      </div>

      <div class="input-group">
        <label for="password-input">Contraseña Maestra</label>
        <div class="input-wrapper">
          <Lock size={16} class="input-icon" />
          <input
            id="password-input"
            type={showPassword ? "text" : "password"}
            bind:value={masterPassword}
            placeholder="Tu contraseña maestra..."
            autocomplete="current-password"
            required
          />
          <button
            type="button"
            class="toggle-btn"
            onclick={() => (showPassword = !showPassword)}
            aria-label={showPassword ? "Ocultar contraseña" : "Ver contraseña"}
            title={showPassword ? "Ocultar contraseña" : "Ver contraseña"}
          >
            {#if showPassword}
              <EyeOff size={16} />
            {:else}
              <Eye size={16} />
            {/if}
          </button>
        </div>
      </div>

      <div class="form-actions">
        <button type="submit" class="btn btn-primary">
          Iniciar Sesión
        </button>
      </div>
    </form>

    <div class="footer-links">
      <button
        type="button"
        class="link-button"
        onclick={() => goto("/login")}
      >
        Ya tengo SilverWarden configurado (Ir a Desbloqueo)
      </button>
    </div>
  </div>
</div>

<style>
  .setup-container {
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 70vh;
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

  .info-banner {
    display: flex;
    align-items: flex-start;
    gap: var(--space-2);
    padding: var(--space-3);
    background-color: color-mix(in srgb, var(--color-primary) 10%, transparent);
    border: 1px solid var(--color-primary);
    border-radius: var(--radius-md);
    color: var(--color-text);
    font-size: var(--font-size-sm);
    line-height: 1.4;
  }

  .info-banner :global(.info-icon) {
    color: var(--color-primary);
    flex-shrink: 0;
    margin-top: 2px;
  }

  .info-text p {
    margin: 0;
  }

  .setup-form {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  .input-group {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
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

  .input-wrapper :global(.input-icon) {
    position: absolute;
    left: var(--space-3);
    color: var(--color-text-muted);
    pointer-events: none;
  }

  .input-wrapper input {
    width: 100%;
    box-sizing: border-box;
    padding: var(--space-2) var(--space-8) var(--space-2) var(--space-8);
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

  .toggle-btn {
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

  .toggle-btn:hover {
    color: var(--color-text);
  }

  .toggle-btn:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: 2px;
  }

  .form-actions {
    margin-top: var(--space-2);
  }

  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: var(--space-2) var(--space-4);
    min-height: 40px;
    border-radius: var(--radius-md);
    font-size: var(--font-size-sm);
    font-family: inherit;
    font-weight: 500;
    cursor: pointer;
    transition: all var(--transition-fast);
    width: 100%;
  }

  .btn-primary {
    background-color: var(--color-primary);
    color: var(--color-primary-text);
    border: 1px solid var(--color-primary);
  }

  .btn-primary:hover {
    background-color: var(--color-primary-hover);
    border-color: var(--color-primary-hover);
  }

  .btn-primary:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: 2px;
  }

  .footer-links {
    text-align: center;
    padding-top: var(--space-2);
    border-top: 1px solid var(--color-border);
  }

  .link-button {
    background: transparent;
    border: none;
    color: var(--color-primary);
    font-size: var(--font-size-sm);
    font-family: inherit;
    cursor: pointer;
    text-decoration: underline;
    transition: opacity var(--transition-fast);
  }

  .link-button:hover {
    opacity: 0.8;
  }

  .link-button:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: 2px;
    border-radius: var(--radius-sm);
  }
</style>

