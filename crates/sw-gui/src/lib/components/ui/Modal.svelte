<script lang="ts">
  import { CheckCircle2, Loader2, Circle } from "lucide-svelte";

  let {
    open = false,
    title = "Desbloqueando Bóveda",
    phases = [
      "Derivando clave maestra (Argon2i)...",
      "Verificando integridad de la clave...",
      "Descifrando bóveda y sesiones...",
    ],
    progress = 0,
  } = $props<{
    open: boolean;
    title?: string;
    phases?: string[];
    progress?: number;
  }>();

  // Determinar la fase visual actual basada en el avance numérico continuo
  let currentPhase = $derived(
    progress >= 100
      ? phases.length
      : Math.min(Math.floor((progress / 95) * phases.length), phases.length - 1)
  );

  let progressPercent = $derived(Math.min(100, Math.max(0, Math.round(progress))));
</script>

{#if open}
  <div class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="modal-title">
    <div class="modal-card">
      <h3 id="modal-title">{title}</h3>

      <div class="phases-checklist">
        {#each phases as phase, index}
          <div
            class="phase-row"
            class:completed={index < currentPhase}
            class:current={index === currentPhase}
            class:pending={index > currentPhase}
          >
            <div class="phase-icon">
              {#if index < currentPhase}
                <CheckCircle2 size={18} color="var(--color-success)" />
              {:else if index === currentPhase}
                <Loader2 size={18} class="spin" color="var(--color-primary)" />
              {:else}
                <Circle size={18} color="var(--color-border)" />
              {/if}
            </div>
            <span class="phase-name">{phase}</span>
          </div>
        {/each}
      </div>

      <div class="progress-bar-container">
        <div class="progress-bar-fill" style="width: {progressPercent}%;"></div>
      </div>
      <span class="progress-percent-label">{progressPercent}%</span>
    </div>
  </div>
{/if}

<style>
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background-color: rgba(0, 0, 0, 0.5);
    backdrop-filter: blur(4px);
    -webkit-backdrop-filter: blur(4px);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
  }

  .modal-card {
    background-color: var(--color-bg-alt);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-md);
    padding: var(--space-6);
    width: 90%;
    max-width: 420px;
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    text-align: left;
  }

  .modal-card h3 {
    margin: 0;
    font-size: var(--font-size-lg);
    color: var(--color-text);
    text-align: center;
  }

  .phases-checklist {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    margin: var(--space-2) 0;
  }

  .phase-row {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-1) 0;
    font-size: var(--font-size-sm);
    color: var(--color-text-muted);
    transition: color var(--transition-fast);
  }

  .phase-row.current {
    color: var(--color-text);
    font-weight: 500;
  }

  .phase-row.completed {
    color: var(--color-text);
  }

  .phase-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .phase-name {
    flex: 1;
  }

  .progress-bar-container {
    width: 100%;
    height: 8px;
    background-color: var(--color-bg);
    border-radius: var(--radius-full);
    overflow: hidden;
    position: relative;
    border: 1px solid var(--color-border);
  }

  .progress-bar-fill {
    height: 100%;
    background-color: var(--color-primary);
    border-radius: var(--radius-full);
    transition: width 0.35s ease;
  }

  .progress-percent-label {
    text-align: right;
    font-size: var(--font-size-sm);
    color: var(--color-text-muted);
    margin-top: calc(-1 * var(--space-2));
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
</style>
