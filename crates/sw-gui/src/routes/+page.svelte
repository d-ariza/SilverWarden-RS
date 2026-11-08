<script lang="ts">
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";
  import { invoke } from "@tauri-apps/api/core";
  import { Shield, Loader2 } from "lucide-svelte";

  interface AgentStatus {
    locked?: boolean;
    has_pin?: boolean;
    logged_in?: boolean;
    error?: string;
  }

  let statusMessage = $state("Iniciando SilverWarden...");

  onMount(async () => {
    try {
      const status = await invoke<AgentStatus>("get_agent_status");

      if (!status || (!status.has_pin && !status.logged_in)) {
        await goto("/setup");
      } else if (status.locked) {
        await goto("/login");
      } else {
        await goto("/vault");
      }
    } catch (e) {
      console.warn("No se pudo conectar al agente, redirigiendo a login:", e);
      await goto("/login");
    }
  });
</script>

<div class="splash-container">
  <div class="splash-content">
    <Shield size={48} color="var(--color-primary)" />
    <div class="spinner-row">
      <Loader2 size={20} class="spin" color="var(--color-primary)" />
      <span>{statusMessage}</span>
    </div>
  </div>
</div>

<style>
  .splash-container {
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 70vh;
  }

  .splash-content {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-4);
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }

  .spinner-row {
    display: flex;
    align-items: center;
    gap: var(--space-2);
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
