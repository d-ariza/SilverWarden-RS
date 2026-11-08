<script lang="ts">
  let { 
    variant = 'primary', 
    type = 'button', 
    disabled = false, 
    onclick 
  } = $props<{
    variant?: 'primary' | 'secondary' | 'danger';
    type?: 'button' | 'submit';
    disabled?: boolean;
    onclick?: (e: MouseEvent) => void;
  }>();

  let baseClass = $derived(`btn btn-${variant}`);
</script>

<button 
  {type} 
  class={baseClass} 
  {disabled} 
  {onclick}
>
  {@render children?.()}
</button>

<style>
  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: var(--space-2) var(--space-4);
    border-radius: var(--radius-md);
    font-family: var(--font-family);
    font-size: var(--font-size-base);
    font-weight: 500;
    cursor: pointer;
    border: 1px solid transparent;
    transition: background-color var(--transition-fast), color var(--transition-fast), opacity var(--transition-fast);
  }

  /* Primary: El botón de acción principal */
  .btn-primary {
    background-color: var(--color-primary);
    color: var(--color-primary-text);
  }
  .btn-primary:hover:not(:disabled) {
    background-color: var(--color-primary-hover);
  }

  /* Secondary: Acciones secundarias (cancelar, etc.) */
  .btn-secondary {
    background-color: transparent;
    border-color: var(--color-border);
    color: var(--color-text);
  }
  .btn-secondary:hover:not(:disabled) {
    background-color: var(--color-skeleton);
  }

  /* Danger: Acciones destructivas (borrar, bloquear) */
  .btn-danger {
    background-color: var(--color-danger);
    color: #ffffff; /* Texto blanco para contraste sobre rojo */
  }
  .btn-danger:hover:not(:disabled) {
    opacity: 0.9;
  }

  /* Estados de accesibilidad */
  .btn:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: 2px;
  }
  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
</style>
