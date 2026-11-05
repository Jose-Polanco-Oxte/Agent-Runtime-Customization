# Auditoría para la limpieza de contratos

Desde la raíz, con Python 3.11+, Rust/Clippy y las dependencias npm ya instaladas:

```powershell
python tools/audit-contracts.py --check-bridge --output target/contract-audit/inventory.json
.\tools\check-cleanup.ps1
```

`check-cleanup.ps1 -InventoryOnly` sólo genera el inventario y comprueba los comandos IPC. No instala dependencias, no ejecuta pruebas y no modifica fuentes del producto. Los comandos Cargo usan `--locked --offline`.

## Qué comprueba

- Inventario ordenado de declaraciones `V1`, `V2`, `_v1`, etc., con archivo, línea, menciones de producción y consumidores de pruebas/ejemplos separados. Excluye comentarios, cadenas e items Rust `#[cfg(test)]` para las menciones de producción.
- Igualdad entre comandos literales `invoke` del bridge, manifiesto de comandos, `generate_handler!` y permisos de la ventana. Una discrepancia devuelve error, incluso si TypeScript y Rust compilan por separado.
- Igualdad de campos del payload `DecisionViewModel` y sus structs/interfaces anidados entre Rust y TypeScript. Detecta campos retirados de un solo extremo. No certifica equivalencia de tipos escalares, atributos serde, enums o reglas de validación.
- Compilación de **todo el workspace y todos sus targets**, primero con features predeterminadas y después con todas las features. Compila consumidores de pruebas y ejemplos sin ejecutarlos.
- Clippy sobre bibliotecas y binarios de producción, mostrando `dead_code`, imports/variables sin uso y visibilidad inalcanzable incluso cuando existe `allow`. Guarda los diagnósticos JSON en `target/contract-audit/compiler.jsonl` y devuelve error si los encuentra.
- Svelte/TypeScript con `noUnusedLocals` y `noUnusedParameters`, más la compilación de tipos del consumidor Webdriver.

## Cómo usarlo al eliminar un contrato

1. Consultar el inventario y el camino desde `main`; una mención o un test no prueba uso real.
2. Eliminar el contrato, sus reexports y los consumidores obsoletos identificados en la auditoría. Para código interno conservado, reducir `pub` a `pub(crate)` o privado donde corresponda.
3. Ejecutar el script completo. Un consumidor Rust/TS tipado que permanezca apuntando al símbolo eliminado debe producir un error de compilación. Una cadena IPC retirada de un solo extremo debe fallar en la comprobación del bridge.

## Límites y estado inicial

El resultado inicial es **rojo**: la auditoría alpha.12 documenta fixtures Rust desactualizadas, un import Svelte sin uso y diagnósticos de visibilidad/código sin uso. El script conserva esos errores y continúa las comprobaciones independientes; no los oculta con una baseline permisiva.

El inventario es léxico, no un grafo semántico de llamadas: cuenta también `impl`, reexports y referencias entre APIs desconectadas. No interpreta macros, otras condiciones `cfg`, imports dinámicos, cadenas IPC calculadas ni exportaciones consumidas fuera del repositorio. Los archivos generados y dependencias no se inventarían. La igualdad IPC se limita al bridge Tauri actual, con comandos literales y permisos locales.

Rust permite APIs `pub` exportadas sin consumidores: `dead_code` no certifica que estén conectadas al CLI. TypeScript también permite exports sin consumidores. Para ambas cosas se requiere el inventario y la revisión de llamadas; no se debe declarar todo el código vivo por obtener una compilación verde. Los avisos generados por macros Tauri tampoco autorizan a borrar sus comandos: el bridge y el registro demuestran su uso.

Estas comprobaciones cubren la plataforma que las ejecuta. Las ramas Unix/Windows deben compilarse en sus plataformas correspondientes; activar todas las features no reemplaza esa matriz. Los fallos de compilación encontrados deben corregirse antes de usar la compilación completa como criterio de aceptación de la limpieza.
