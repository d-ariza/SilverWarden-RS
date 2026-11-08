<script lang="ts">
  let { 
    label, 
    type = 'text', 
    placeholder = '', 
    value = $bindable(''), 
    disabled = false,
    error = ''
  } = $props<{
    label: string;
    type?: 'text' | 'password' | 'email';
    placeholder?: string;
    value?: string;
    disabled?: boolean;
    error?: string;
  }>();
</script>

<div class="input-group">
  <label for={label}>{label}</label>
  <input 
    id={label}
    {type} 
    {placeholder} 
    bind:value 
    {disabled}
    class:has-error={error}
  />
  {#if error}
    <span class="error-text">{error}</span>
  {/if}
</div>

<style>
  .input-group {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    margin-bottom: var(--space-4);
    width: 100%;
  }

  label {
    font-size: var(--font-size-sm);
    color: var(--color-text-muted);
    font-weight: 500;
  }

  input {
    padding: var(--space-2) var(--space-3);
    border-radius: var(--radius-md);
    border: 1px solid var(--color-border);
    background-color: var(--color-bg-alt);
    color: var(--color-text);
    font-family: var(--font-family);
    font-size: var(--font-size-base);
    transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
  }

  input:focus {
    outline: none;
    border-color: var(--color-primary);
    box-shadow: 0 0 0 2px var(--color-skeleton);
  }

  input:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  input.has-error {
    border-color: var(--color-danger);
  }

  .error-text {
    font-size: var(--font-size-sm);
    color: var(--color-danger);
  }
</style>
