<script lang="ts">
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";
  import {
    Terminal,
    Plus,
    Upload,
    Trash2,
    Copy,
    Check,
    WifiOff,
    AlertCircle,
    RefreshCw,
    KeyRound,
  } from "lucide-svelte";
  import { agent } from "$lib/api/agent";
  import type { SshKeySummary } from "$lib/types/generated/SshKeySummary";
  import { vaultState } from "$lib/state/vault.svelte";
  import { isDisconnectedError } from "$lib/state/transitions";

  let keys = $state<SshKeySummary[]>([]);
  let hasLoadedInitial = $state(false);
  let fetching = $state(true);
  let loadError = $state<string | null>(null);
  let disconnected = $state(false);

  let createName = $state("");
  let createKeyType = $state<"ed25519" | "rsa">("ed25519");
  let creating = $state(false);

  let importName = $state("");
  let importPem = $state("");
  let importing = $state(false);

  let actionFeedback = $state("");
  let actionError = $state("");
  let copiedKeyId = $state<string | null>(null);

  let pendingDelete = $state<SshKeySummary | null>(null);
  let deleting = $state(false);
  let deleteDialogEl = $state<HTMLDialogElement | null>(null);

  function messageFromError(err: unknown): string {
    return err instanceof Error ? err.message : typeof err === "string" ? err : String(err);
  }

  async function loadKeys() {
    fetching = true;
    loadError = null;
    disconnected = false;

    const status = await vaultState.refreshStatus();
    if (status.state === "locked" || status.state === "logged_out") {
      fetching = false;
      hasLoadedInitial = true;
      await goto("/login");
      return;
    }
    if (status.state === "needs_setup") {
      fetching = false;
      hasLoadedInitial = true;
      await goto("/setup");
      return;
    }
    if (status.state === "disconnected") {
      disconnected = true;
      fetching = false;
      hasLoadedInitial = true;
      return;
    }
    if (status.state === "error") {
      loadError = status.message;
      fetching = false;
      hasLoadedInitial = true;
      return;
    }

    try {
      const [res] = await Promise.all([
        agent.listSshKeys(),
        new Promise((r) => setTimeout(r, 250)),
      ]);
      keys = Array.isArray(res) ? res : [];
    } catch (err) {
      const msg = messageFromError(err);
      if (isDisconnectedError(msg)) {
        disconnected = true;
      } else {
        loadError = msg;
      }
      keys = [];
    } finally {
      fetching = false;
      hasLoadedInitial = true;
    }
  }

  async function handleCreateKey() {
    const trimmed = createName.trim();
    if (!trimmed) {
      actionError = "Indica un nombre para la nueva clave SSH.";
      return;
    }
    creating = true;
    actionError = "";
    actionFeedback = "";
    try {
      const created = await agent.newSshKey(trimmed, createKeyType);
      createName = "";
      actionFeedback = `Clave SSH "${created.name}" generada correctamente.`;
      await loadKeys();
    } catch (err) {
      const msg = messageFromError(err);
      if (isDisconnectedError(msg)) {
        disconnected = true;
      } else {
        actionError = msg;
      }
    } finally {
      creating = false;
    }
  }

  async function handleImportKey() {
    const trimmedName = importName.trim();
    const trimmedPem = importPem.trim();
    if (!trimmedName || !trimmedPem) {
      actionError = "Indica el nombre y el contenido PEM de la clave privada.";
      return;
    }
    importing = true;
    actionError = "";
    actionFeedback = "";
    try {
      const imported = await agent.importSshKey(trimmedName, trimmedPem);
      importName = "";
      importPem = "";
      actionFeedback = `Clave SSH "${imported.name}" importada correctamente.`;
      await loadKeys();
    } catch (err) {
      const msg = messageFromError(err);
      if (isDisconnectedError(msg)) {
        disconnected = true;
      } else {
        actionError = msg;
      }
    } finally {
      importing = false;
    }
  }

  function openDeleteDialog(key: SshKeySummary) {
    actionError = "";
    actionFeedback = "";
    pendingDelete = key;
    deleteDialogEl?.showModal();
  }

  function closeDeleteDialog() {
    deleteDialogEl?.close("cancel");
  }

  function handleDialogClose() {
    if (deleteDialogEl) {
      deleteDialogEl.returnValue = "";
    }
    pendingDelete = null;
  }

  async function confirmDeleteKey() {
    if (!pendingDelete?.id) return;
    const targetName = pendingDelete.name;
    const targetId = pendingDelete.id;
    deleting = true;
    actionError = "";
    actionFeedback = "";
    try {
      await agent.deleteSshKey(targetId);
      closeDeleteDialog();
      actionFeedback = `Clave SSH "${targetName}" eliminada.`;
      await loadKeys();
    } catch (err) {
      const msg = messageFromError(err);
      closeDeleteDialog();
      if (isDisconnectedError(msg)) {
        disconnected = true;
      } else {
        actionError = msg;
      }
    } finally {
      deleting = false;
    }
  }

  async function handleCopy(text: string, fieldKey: string) {
    if (!text) return;
    try {
      await agent.copyToClipboard(text);
      copiedKeyId = fieldKey;
      setTimeout(() => {
        if (copiedKeyId === fieldKey) copiedKeyId = null;
      }, 2000);
    } catch (err) {
      actionError = messageFromError(err);
    }
  }

  onMount(() => {
    loadKeys();
  });
</script>

<div class="ssh-page">
  <header class="page-header">
    <div>
      <div class="title-row">
        <Terminal size={24} color="var(--color-primary)" />
        <h1>Claves SSH</h1>
      </div>
      <p class="subtitle">Gestiona, genera e importa tus claves SSH almacenadas en la bóveda</p>
    </div>

    <button
      type="button"
      class="btn btn-secondary"
      onclick={loadKeys}
      disabled={fetching}
      aria-label="Actualizar lista de claves SSH"
    >
      <span class="icon-wrap" class:spin={fetching}>
        <RefreshCw size={16} />
      </span>
      <span>Actualizar</span>
    </button>
  </header>

  {#if actionFeedback}
    <div class="banner success" role="status" aria-live="polite">
      <Check size={18} color="var(--color-success)" />
      <span>{actionFeedback}</span>
    </div>
  {/if}

  {#if actionError}
    <div class="banner danger" role="alert">
      <AlertCircle size={18} color="var(--color-danger)" />
      <span>{actionError}</span>
    </div>
  {/if}

  <div class="ssh-layout">
    <section class="panel keys-panel" aria-label="Claves SSH registradas">
      <h2>Claves registradas</h2>

      {#if !hasLoadedInitial || fetching}
        <div class="skeletons-wrapper" aria-busy="true" aria-label="Cargando claves SSH">
          {#each [1, 2, 3] as _}
            <div class="skeleton-card">
              <div class="skeleton-line skeleton-title"></div>
              <div class="skeleton-line skeleton-subtitle"></div>
            </div>
          {/each}
        </div>
      {:else if disconnected}
        <div class="state-card warning" role="alert">
          <WifiOff size={32} color="var(--color-warning)" />
          <h3>Agente desconectado</h3>
          <p>No se pudo contactar con <code>sw-agent</code>. Inicia el demonio para ver tus claves SSH.</p>
          <button type="button" class="btn btn-primary" onclick={loadKeys}>
            Reintentar conexión
          </button>
        </div>
      {:else if loadError}
        <div class="state-card danger" role="alert">
          <AlertCircle size={32} color="var(--color-danger)" />
          <h3>Error al cargar claves</h3>
          <p>{loadError}</p>
          <button type="button" class="btn btn-primary" onclick={loadKeys}>
            Reintentar
          </button>
        </div>
      {:else if keys.length === 0}
        <div class="state-card">
          <KeyRound size={32} color="var(--color-text-muted)" />
          <h3>No hay claves SSH registradas en la bóveda</h3>
          <p>Genera una clave nueva o importa una existente en formato PEM usando el panel lateral.</p>
        </div>
      {:else}
        <ul class="keys-list">
          {#each keys as key (key.id ?? `${key.name}-${key.fingerprint}`)}
            <li class="key-card">
              <div class="key-card-top">
                <div class="key-title-wrap">
                  <span class="key-name">{key.name}</span>
                  <span class="key-badge">{key.key_type}</span>
                </div>

                <button
                  type="button"
                  class="icon-action-btn danger"
                  onclick={() => openDeleteDialog(key)}
                  disabled={!key.id}
                  title={key.id ? `Eliminar clave ${key.name}` : "Clave sin identificador de bóveda"}
                  aria-label={`Eliminar clave ${key.name}`}
                >
                  <Trash2 size={16} />
                </button>
              </div>

              <div class="key-meta">
                <div class="meta-row">
                  <span class="meta-label">Huella (SHA256)</span>
                  <div class="meta-value-row">
                    <code class="meta-code">{key.fingerprint}</code>
                    <button
                      type="button"
                      class="icon-action-btn"
                      onclick={() => handleCopy(key.fingerprint, `${key.name}-fp`)}
                      aria-label={`Copiar huella de ${key.name}`}
                      title="Copiar huella"
                    >
                      {#if copiedKeyId === `${key.name}-fp`}
                        <Check size={15} color="var(--color-success)" />
                      {:else}
                        <Copy size={15} />
                      {/if}
                    </button>
                  </div>
                </div>

                <div class="meta-row">
                  <span class="meta-label">Clave pública</span>
                  <div class="meta-value-row">
                    <code class="meta-code meta-code-truncate">{key.public_key}</code>
                    <button
                      type="button"
                      class="icon-action-btn"
                      onclick={() => handleCopy(key.public_key, `${key.name}-pub`)}
                      aria-label={`Copiar clave pública de ${key.name}`}
                      title="Copiar clave pública"
                    >
                      {#if copiedKeyId === `${key.name}-pub`}
                        <Check size={15} color="var(--color-success)" />
                      {:else}
                        <Copy size={15} />
                      {/if}
                    </button>
                  </div>
                </div>
              </div>
            </li>
          {/each}
        </ul>
      {/if}
    </section>

    <aside class="forms-column" aria-label="Acciones de claves SSH">
      <section class="panel">
        <div class="panel-heading">
          <Plus size={18} color="var(--color-primary)" />
          <h2>Generar nueva clave SSH</h2>
        </div>

        <form class="stack-form" onsubmit={(e) => { e.preventDefault(); handleCreateKey(); }}>
          <div class="field-group">
            <label for="create-ssh-name">Nombre de la clave</label>
            <input
              id="create-ssh-name"
              type="text"
              bind:value={createName}
              placeholder="Ej: portátil-trabajo"
              required
              disabled={creating || disconnected}
            />
          </div>

          <div class="field-group">
            <label for="create-ssh-type">Algoritmo</label>
            <select
              id="create-ssh-type"
              bind:value={createKeyType}
              disabled={creating || disconnected}
            >
              <option value="ed25519">Ed25519 (Recomendado)</option>
              <option value="rsa">RSA 4096</option>
            </select>
          </div>

          <button type="submit" class="btn btn-primary" disabled={creating || disconnected}>
            <Plus size={16} />
            <span>{creating ? "Generando..." : "Generar clave"}</span>
          </button>
        </form>
      </section>

      <section class="panel">
        <div class="panel-heading">
          <Upload size={18} color="var(--color-primary)" />
          <h2>Importar clave privada (PEM)</h2>
        </div>

        <form class="stack-form" onsubmit={(e) => { e.preventDefault(); handleImportKey(); }}>
          <div class="field-group">
            <label for="import-ssh-name">Nombre de la clave</label>
            <input
              id="import-ssh-name"
              type="text"
              bind:value={importName}
              placeholder="Ej: servidor-prod"
              required
              disabled={importing || disconnected}
            />
          </div>

          <div class="field-group">
            <label for="import-ssh-pem">Clave privada PEM</label>
            <textarea
              id="import-ssh-pem"
              rows={5}
              bind:value={importPem}
              placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
              required
              disabled={importing || disconnected}
            ></textarea>
          </div>

          <button type="submit" class="btn btn-secondary" disabled={importing || disconnected}>
            <Upload size={16} />
            <span>{importing ? "Importando..." : "Importar clave PEM"}</span>
          </button>
        </form>
      </section>
    </aside>
  </div>
</div>

<dialog
  bind:this={deleteDialogEl}
  class="confirm-dialog"
  aria-labelledby="delete-ssh-title"
  onclose={handleDialogClose}
>
  <h2 id="delete-ssh-title">Eliminar clave SSH</h2>
  <p class="dialog-copy">
    ¿Seguro que deseas eliminar la clave <strong>{pendingDelete?.name ?? ""}</strong> de la bóveda?
    Esta acción no se puede deshacer.
  </p>
  <div class="dialog-actions">
    <!-- autofocus en la acción segura por guía de diálogos destructivos -->
    <!-- svelte-ignore a11y_autofocus -->
    <button
      type="button"
      class="btn btn-secondary"
      autofocus
      onclick={closeDeleteDialog}
      disabled={deleting}
    >
      Cancelar
    </button>
    <button
      type="button"
      class="btn btn-danger"
      onclick={confirmDeleteKey}
      disabled={deleting}
    >
      {deleting ? "Eliminando..." : "Eliminar clave"}
    </button>
  </div>
</dialog>

<style>
  .ssh-page {
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
    margin: 0 0 var(--space-3) 0;
    font-size: var(--font-size-lg);
    color: var(--color-text);
  }

  .subtitle {
    margin: var(--space-1) 0 0 0;
    font-size: var(--font-size-sm);
    color: var(--color-text-muted);
  }

  .banner {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-3) var(--space-4);
    border-radius: var(--radius-md);
    border: 1px solid var(--color-border);
    background-color: var(--color-bg-alt);
    font-size: var(--font-size-sm);
  }

  .banner.success {
    border-color: var(--color-success);
  }

  .banner.danger {
    border-color: var(--color-danger);
    color: var(--color-danger);
  }

  .ssh-layout {
    display: grid;
    grid-template-columns: minmax(0, 1.4fr) minmax(280px, 1fr);
    gap: var(--space-6);
    align-items: start;
  }

  .forms-column {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .panel {
    background-color: var(--color-bg-alt);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-sm);
    padding: var(--space-4);
  }

  .panel-heading {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin-bottom: var(--space-3);
  }

  .panel-heading h2 {
    margin: 0;
  }

  .keys-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  .key-card {
    background-color: var(--color-bg);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    padding: var(--space-3);
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  .key-card-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: var(--space-2);
  }

  .key-title-wrap {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    flex-wrap: wrap;
  }

  .key-name {
    font-weight: 600;
    font-size: var(--font-size-base);
    color: var(--color-text);
  }

  .key-badge {
    padding: 2px var(--space-2);
    border-radius: var(--radius-full);
    border: 1px solid var(--color-border);
    background-color: var(--color-bg-alt);
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
    font-family: monospace;
  }

  .key-meta {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .meta-row {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .meta-label {
    font-size: var(--font-size-sm);
    color: var(--color-text-muted);
    font-weight: 500;
  }

  .meta-value-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-2);
    padding: var(--space-1) var(--space-2);
    border-radius: var(--radius-sm);
    border: 1px solid var(--color-border);
    background-color: var(--color-bg-alt);
  }

  .meta-code {
    font-family: monospace;
    font-size: var(--font-size-sm);
    color: var(--color-text);
    overflow-wrap: anywhere;
  }

  .meta-code-truncate {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .icon-action-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 36px;
    min-height: 36px;
    border-radius: var(--radius-sm);
    border: 1px solid transparent;
    background: transparent;
    color: var(--color-text-muted);
    cursor: pointer;
    flex-shrink: 0;
  }

  .icon-action-btn:hover:not(:disabled) {
    background-color: var(--color-skeleton);
    color: var(--color-text);
  }

  .icon-action-btn.danger:hover:not(:disabled) {
    color: var(--color-danger);
    border-color: var(--color-danger);
  }

  .icon-action-btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  .stack-form {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
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

  .field-group input,
  .field-group select,
  .field-group textarea {
    width: 100%;
    padding: var(--space-2) var(--space-3);
    min-height: 44px;
    border-radius: var(--radius-md);
    border: 1px solid var(--color-border);
    background-color: var(--color-bg);
    color: var(--color-text);
    font-family: inherit;
    font-size: var(--font-size-sm);
    box-sizing: border-box;
  }

  .field-group textarea {
    min-height: 112px;
    font-family: monospace;
    resize: vertical;
  }

  .state-card {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    gap: var(--space-2);
    padding: var(--space-6) var(--space-4);
    border-radius: var(--radius-md);
    border: 1px dashed var(--color-border);
    background-color: var(--color-bg);
  }

  .state-card.warning {
    border-style: solid;
    border-color: var(--color-warning);
  }

  .state-card.danger {
    border-style: solid;
    border-color: var(--color-danger);
  }

  .state-card h3 {
    margin: 0;
    font-size: var(--font-size-base);
    color: var(--color-text);
  }

  .state-card p {
    margin: 0;
    font-size: var(--font-size-sm);
    color: var(--color-text-muted);
    max-width: 380px;
  }

  .skeletons-wrapper {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  .skeleton-card {
    padding: var(--space-3);
    border-radius: var(--radius-md);
    border: 1px solid var(--color-border);
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .skeleton-line {
    height: 14px;
    border-radius: var(--radius-sm);
    background-color: var(--color-skeleton);
  }

  .skeleton-title {
    width: 45%;
  }

  .skeleton-subtitle {
    width: 85%;
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

  .btn-danger {
    background-color: var(--color-danger);
    color: var(--color-danger-text);
  }

  .icon-wrap {
    display: inline-flex;
    align-items: center;
  }

  /* Reglas para native <dialog> según modern-web-guidance */
  .confirm-dialog {
    max-width: 440px;
    width: 90%;
    padding: var(--space-6);
    border-radius: var(--radius-md);
    border: 1px solid var(--color-border);
    background-color: var(--color-bg-alt);
    color: var(--color-text);
    box-shadow: var(--shadow-md);
  }

  .confirm-dialog[open] {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  .confirm-dialog:modal {
    overscroll-behavior: contain;
  }

  .confirm-dialog::backdrop {
    background-color: rgba(0, 0, 0, 0.55);
    backdrop-filter: blur(2px);
    overflow: hidden;
    overscroll-behavior: contain;
  }

  .dialog-copy {
    margin: 0;
    font-size: var(--font-size-sm);
    color: var(--color-text-muted);
    line-height: 1.5;
  }

  .dialog-actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--space-3);
    margin-top: var(--space-2);
  }

  @media (max-width: 820px) {
    .ssh-layout {
      grid-template-columns: 1fr;
    }
  }
</style>
