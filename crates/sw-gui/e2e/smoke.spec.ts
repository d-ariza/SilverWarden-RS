import { expect, test } from '@playwright/test';

test.describe('SilverWarden GUI smoke E2E', () => {
  test('arranca la aplicación principal sin errores de consola y con soporte de temas', async ({
    page,
  }) => {
    const pageErrors: string[] = [];
    page.on('pageerror', (err) => pageErrors.push(err.message));

    await page.goto('/');
    await expect(page.locator('html')).toHaveAttribute('lang', 'es');
    await expect(page.getByRole('heading', { name: 'SilverWarden', level: 1 })).toBeVisible();

    const modeButton = page.getByRole('button', { name: 'Alternar modo claro u oscuro' });
    await expect(modeButton).toBeVisible();
    await modeButton.click();
    await expect(page.locator('html')).toHaveAttribute('data-mode', 'dark');

    expect(pageErrors).toEqual([]);
  });

  test('las rutas /login, /setup, /vault, /ssh y /settings renderizan sin errores', async ({
    page,
  }) => {
    const pageErrors: string[] = [];
    page.on('pageerror', (err) => pageErrors.push(err.message));

    await page.goto('/login');
    await expect(page.getByRole('heading', { name: 'Bóveda SilverWarden', level: 1 })).toBeVisible();
    const pinInput = page.getByLabel('PIN de Desbloqueo');
    await expect(pinInput).toHaveAttribute('type', 'password');
    const togglePin = page.getByRole('button', { name: 'Mostrar PIN' });
    await togglePin.click();
    await expect(togglePin).toHaveAttribute('aria-pressed', 'true');
    await expect(pinInput).toHaveAttribute('type', 'text');

    await page.goto('/setup');
    await expect(
      page.getByRole('heading', { name: 'Bienvenido a SilverWarden', level: 1 })
    ).toBeVisible();

    await page.goto('/vault');
    await expect(
      page.getByRole('heading', { name: 'Bóveda de credenciales', level: 1 })
    ).toBeAttached();

    await page.goto('/ssh');
    await expect(page.getByRole('heading', { name: 'Claves SSH', level: 1 })).toBeVisible();

    await page.goto('/settings');
    await expect(
      page.getByRole('heading', { name: 'Ajustes y Seguridad', level: 1 })
    ).toBeVisible();

    expect(pageErrors).toEqual([]);
  });
});
