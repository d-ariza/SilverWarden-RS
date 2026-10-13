<script lang="ts">
  let status = $state("Bloqueado");
  let pin = $state("");
  let isUnlocking = $state(false);

  function handleUnlock() {
    if (!pin) return;
    isUnlocking = true;
    setTimeout(() => {
      status = "Desbloqueado";
      isUnlocking = false;
      pin = "";
    }, 600);
  }

  function handleLock() {
    status = "Bloqueado";
  }
</script>

<main class="container">
  <header class="header">
    <div class="logo-badge">🛡️</div>
    <h1>silverWarden</h1>
    <span class="badge" class:unlocked={status === "Desbloqueado"}>{status}</span>
  </header>

  <section class="card">
    {#if status === "Bloqueado"}
      <h2>Desbloquear Almacén</h2>
      <p class="subtitle">Introduce tu PIN de sesión para acceder a credenciales y SSH Agent</p>
      <form onsubmit={(e) => { e.preventDefault(); handleUnlock(); }} class="form">
        <input
          type="password"
          bind:value={pin}
          placeholder="PIN de acceso..."
          autocomplete="current-password"
          class="input"
        />
        <button type="submit" class="btn primary" disabled={isUnlocking || !pin}>
          {isUnlocking ? "Verificando..." : "Desbloquear"}
        </button>
      </form>
    {:else}
      <h2>Almacén Activo</h2>
      <p class="subtitle">Conexión con el agente IPC establecida · SSH Agent activo</p>
      <div class="actions">
        <button onclick={handleLock} class="btn danger">Bloquear ahora</button>
      </div>
    {/if}
  </section>
</main>

<style>
  .container {
    max-width: 600px;
    margin: 40px auto;
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 24px;
  }

  .header {
    display: flex;
    align-items: center;
    gap: 16px;
  }

  .logo-badge {
    font-size: 2rem;
  }

  h1 {
    font-size: 1.8rem;
    font-weight: 700;
    color: #f8fafc;
  }

  .badge {
    margin-left: auto;
    font-size: 0.8rem;
    padding: 4px 10px;
    border-radius: 9999px;
    background: #e11d48;
    color: white;
    font-weight: 600;
  }

  .badge.unlocked {
    background: #10b981;
  }

  .card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 16px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
  }

  h2 {
    font-size: 1.25rem;
    font-weight: 600;
    color: #f8fafc;
  }

  .subtitle {
    color: #94a3b8;
    font-size: 0.95rem;
  }

  .form {
    display: flex;
    flex-direction: column;
    gap: 12px;
    margin-top: 8px;
  }

  .input {
    background: #0f172a;
    border: 1px solid #475569;
    border-radius: 8px;
    padding: 10px 14px;
    color: #f8fafc;
    font-size: 1rem;
    outline: none;
    transition: border-color 0.2s;
  }

  .input:focus {
    border-color: #38bdf8;
  }

  .btn {
    border: none;
    border-radius: 8px;
    padding: 10px 16px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: opacity 0.2s, background-color 0.2s;
  }

  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .btn.primary {
    background: #2563eb;
    color: white;
  }

  .btn.primary:hover:not(:disabled) {
    background: #1d4ed8;
  }

  .btn.danger {
    background: #e11d48;
    color: white;
  }

  .btn.danger:hover {
    background: #be123c;
  }
</style>
