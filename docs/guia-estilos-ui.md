# Guía de Estilos y Componentes UI (M7)

**Regla de Oro:** La IA NUNCA debe hardcodear colores, tamaños o márgenes. SIEMPRE debe usar las variables CSS definidas en `src/lib/design/tokens.css` y los temas.

## 1. Variables Globales (Design Tokens)
- **Colores:** `var(--color-bg)`, `var(--color-bg-alt)`, `var(--color-text)`, `var(--color-text-muted)`, `var(--color-primary)`, `var(--color-primary-hover)`, `var(--color-primary-text)`, `var(--color-border)`, `var(--color-danger)`, `var(--color-success)`, `var(--color-skeleton)`.
- **Espaciados:** `var(--space-1)` (4px), `var(--space-2)` (8px), `var(--space-3)` (12px), `var(--space-4)` (16px), `var(--space-6)` (24px), `var(--space-8)` (32px).
- **Bordes:** `var(--radius-sm)` (4px), `var(--radius-md)` (8px), `var(--radius-lg)` (12px), `var(--radius-full)` (9999px).
- **Sombras:** `var(--shadow-sm)`, `var(--shadow-md)`.
- **Transiciones:** `var(--transition-fast)` (150ms ease).
- **Tipografía:** `var(--font-size-sm)`, `var(--font-size-base)`, `var(--font-size-lg)`, `var(--font-size-xl)`, `var(--font-family)`.

## 2. Reglas de Componentes
- **Botones:** Deben usar las variables de color de acento (`--color-primary`) y texto de contraste (`--color-primary-text`). Tener estados `hover`, `focus` y `disabled`.
- **Inputs:** Fondo `var(--color-bg-alt)`, borde `var(--color-border)`, foco con `var(--color-primary)`.
- **Skeletons:** Usar `var(--color-skeleton)` con una animación de pulso. Se usan SIEMPRE en lugar de un spinner genérico para cargar listas o datos de contenido.
- **Cards/Contenedores:** Fondo `var(--color-bg-alt)`, borde `var(--color-border)`, sombra `var(--shadow-sm)`, radio `var(--radius-md)`.

## 3. Accesibilidad y Contraste
- El texto debe ser siempre legible en modo claro y oscuro respetando los contrastes de los 3 temas (Fluent, Cupertino, Breeze).
- Los botones interactivos deben tener un tamaño mínimo de clic de 40x40px (usar `var(--space-6)` para padding).
- Usar `aria-label` en botones que solo contengan un icono.

## 4. Comportamiento (Svelte 5)
- Usar `$state` para estado local y `$derived` para valores calculados.
- Los eventos se manejan sin dos puntos (ej. `onclick`, `onchange`).
- En Svelte 5, usar snippets (`{#snippet ...}`) y renderizado explícito (`{@render children()}`) en lugar de `<slot />`.
- Para componentes responsivos internos (listas, splitters), preferir CSS Container Queries (`container-type: inline-size` y `@container`).
- La comunicación con el backend se hace mediante `import { invoke } from '@tauri-apps/api/core';`.

## 5. Iconografía (lucide-svelte)
- Usar exclusivamente `lucide-svelte` para todos los iconos de la interfaz (ojo de contraseña, copiar, candado, refresh, check, etc.).
- Importar únicamente los iconos individuales necesarios (ej. `import { Eye, Copy, Check } from 'lucide-svelte';`) para mantener el bundle ligero y aprovechar el tree-shaking.
- Los iconos deben heredar el color del texto mediante `currentColor` o usar las variables de color del tema.

## 6. Feedback y Acciones
- **Acciones rápidas (ej. Copiar al portapapeles):** Deben ofrecer feedback visual inmediato en el propio botón, cambiando temporalmente el icono a un check (`Check`) durante 2 segundos antes de volver al icono original.
- **Acciones importantes y alertas del sistema (ej. Error de sincronización, Vault guardado):** Deben utilizar un componente `Toast` global no intrusivo en la esquina superior/inferior de la aplicación.

## 7. Estabilidad de Layout (Regla General)
Los botones, inputs, selects y cualquier elemento interactivo deben tener un tamaño predecible. El tamaño fijo o el `min-width` es la regla general para evitar saltos visuales cuando cambia el texto, el estado de carga o el idioma.

- **Botones de acción:** `min-width: 120px` (o el ancho de su texto más largo).
- **Inputs y Selects:** `width: 100%` si están en formularios, o un ancho fijo si están en barras de herramientas.
- **Excepción:** Solo permitimos que un botón cambie de tamaño si su contenido es dinámico por naturaleza (ej. un botón que dice "Guardar (3)" y el número cambia).

---

## 8. Principios de Diseño Adaptados (Basados en HIG, Material 3 y WCAG)
Este es nuestro "manifiesto de UI". La IA debe seguirlo en cada componente.

### 8.1 Claridad ante todo (Apple HIG)
*   **Texto legible:** El texto nunca debe ser más pequeño que `var(--font-size-sm)` (0.875rem), excepto para metadatos muy secundarios.
*   **Iconos familiares:** Usa iconos que la gente ya conozca (lupa para buscar, ojo para ver, candado para bloquear). No inventes metáforas raras.
*   **Feedback inmediato:** Cada clic debe tener una reacción visual en menos de 100ms (hover, foco, o un spinner si tarda más).

### 8.2 Jerarquía y Espaciado (Refactoring UI)
*   **Un solo protagonista:** En cada pantalla, debe haber un solo botón "primario" (el azul). Los demás son secundarios (grises o con borde).
*   **Espacio en blanco:** Usa `var(--space-4)` o `var(--space-6)` entre secciones importantes. El espacio en blanco no es "desperdicio", es lo que hace que la UI respire.
*   **Sombras con propósito:** Usa `--shadow-sm` para elementos en reposo y `--shadow-md` para elementos que flotan (modales o menús desplegables).

### 8.3 Consistencia y Componentes (Material Design 3)
*   **Formas consistentes:** Todos los botones deben tener el mismo `border-radius` (`var(--radius-md)`). No mezcles botones cuadrados con botones redondos.
*   **Estados claros:** Un botón deshabilitado debe ser visualmente distinto (opacidad 0.5, cursor no permitido) y no debe reaccionar al clic.
*   **Navegación predecible:** La barra lateral (sidebar) siempre debe estar en el mismo lugar y tener los mismos iconos.

### 8.4 Accesibilidad Innegociable (WCAG 2.1 AA)
*   **Contraste:** El texto debe tener un contraste mínimo de 4.5:1 con el fondo. Nuestros temas (Fluent, Cupertino, Breeze) ya cumplen esto, pero la IA debe verificar que no se rompa.
*   **Foco visible:** Cualquier elemento interactivo (botón, input, enlace) debe tener un `outline` visible al navegar con la tecla `Tab`. Nunca uses `outline: none` sin un reemplazo visual.
*   **Etiquetas ARIA:** Los botones que solo tienen un icono (como el ojo del PIN o el botón de copiar) deben tener un `aria-label` descriptivo (ej. `aria-label="Mostrar contraseña"`).

---

## 9. Experiencia Desktop Nativa con Tauri (Eliminar el "Feel de Web")
Para que la aplicación se sienta como un software de escritorio profesional y no como una página web enmarcada, deben aplicarse estrictamente estas directrices:

### 9.1 Bloqueo de Selección Accidental
*   **Regla general:** Aplicar `user-select: none;` (`-webkit-user-select: none;`) en toda la estructura base de la app (topbars, sidebars, botones, encabezados, tarjetas y listas).
*   **Excepciones selectivas:** Únicamente habilitar `user-select: text;` en campos donde el usuario explícitamente necesite copiar texto (valores de contraseñas, nombres de usuario, tokens, logs o inputs de texto).

### 9.2 Desactivación del Menú Contextual del Navegador
*   En producción, debe bloquearse el menú contextual web por defecto (`contextmenu`) que muestra opciones como *"Inspeccionar elemento"* o *"Recargar página"*.
*   Si se requiere menú contextual, debe implementarse mediante menús nativos de Tauri (`tauri::menu::ContextMenu`) o un componente popover contextual diseñado acorde al tema.

### 9.3 Prevención de Arrastre Fantasma
*   Las imágenes, iconos SVG y enlaces no deben ser arrastrables.
*   Aplicar `-webkit-user-drag: none;` y el atributo HTML `draggable="false"` para evitar la imagen fantasma semitransparente al hacer clic y mover el ratón accidentalmente.

### 9.4 Escala y Zoom Fijos
*   Una aplicación de escritorio debe controlar su densidad visual.
*   Prevenir combinaciones de teclas de zoom del motor web (`Ctrl + +`, `Ctrl + -`, `Ctrl + Rueda`) en producción para no romper las proporciones ni el layout de las ventanas.

### 9.5 Áreas de Arrastre de Ventana (*Window Dragging*)
*   En ventanas personalizadas o barras de título integradas, usar el atributo `data-tauri-drag-region` en la cabecera para permitir que el usuario mueva la ventana arrastrando la barra.
*   **Aislamiento de controles:** Todo elemento interactivo dentro de un área con `data-tauri-drag-region` (botones, selects, inputs) debe capturar sus propios eventos de ratón para que el clic no sea interceptado por el arrastre.

---

## 10. Filosofía Keyboard-First y Atajos de Escritorio
Los usuarios de escritorio operan frecuentemente a través del teclado. La interfaz debe responder a patrones de accesibilidad rápida:

*   **`Ctrl + F` / `Cmd + F`:** Enfocar de inmediato el campo de búsqueda de la lista principal.
*   **`Escape`:** Cerrar cualquier modal, diálogo o cancelar la búsqueda activa devolviendo el foco al contenedor anterior.
*   **`Ctrl + L` / `Cmd + L`:** Bloquear la bóveda o cerrar sesión de manera instantánea.
*   **Navegación en listas:** Soportar navegación vertical con flechas (`↑` / `↓`) y selección con `Enter`.
*   **Foco sin trampas:** El orden de tabulación (`Tab` / `Shift + Tab`) debe ser secuencial, lógico y visible en todo momento.

---

## 11. Resiliencia del Enlace IPC (Backend Desktop)
A diferencia de una web donde un fallo del servidor resulta en una página de error HTTP, en Tauri la app convive con procesos locales (daemons, sockets IPC, subprocesos Rust):

*   **Cero congelamientos:** Ninguna llamada `invoke` debe bloquear el hilo de renderizado. Siempre deben manejarse con promesas asíncronas y bloques `try/catch`.
*   **Feedback de reconexión:** Si el daemon o socket no responde o se reinicia, la UI no debe romperse; debe mostrar un estado degradado claro (*"Reconectando al agente..."*) con reintentos manuales o automáticos controlados.
*   **Retraso visual mínimo:** Operaciones asíncronas ultrarrápidas deben mantener un retraso visual mínimo (ej. 200–250ms) al renderizar skeletons para evitar destellos y saltos visuales en pantalla.

---

## 12. Modales HTML vs Diálogos Nativos del Sistema
*   **Modales HTML/Svelte:** Utilizarlos para flujos interactivos continuos dentro del contexto de la aplicación (ej. progreso de derivación de claves, checklists de desbloqueo, formularios de edición o previsualización de datos).
*   **Diálogos Nativos (`@tauri-apps/plugin-dialog`):** Reservarlos para:
    1. Confirmaciones destructivas irreversibles (*"¿Eliminar permanentemente este registro?"*).
    2. Interacción con el sistema de archivos del sistema operativo (*"Importar archivo .csv / .json"*, *"Guardar copia de seguridad"*).


