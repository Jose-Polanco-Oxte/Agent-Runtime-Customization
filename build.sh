#!/usr/bin/env bash
# ==============================================================================
# Arc Core and Decision UI - Unified Build & Installation Script
# ==============================================================================
set -euo pipefail

INSTALL=false
INSTALL_DIR=""
PROFILE="release"
SKIP_FRONTEND=false
SKIP_NPM_INSTALL=false
CLEAN=false
CHECK=false

print_help() {
    cat << 'EOF'
Uso: ./build.sh [OPCIONES]

Opciones:
  --install              Instala arc vía 'cargo install --path . --force' y copia arc-decision-ui-host
                         al mismo directorio bin ($CARGO_HOME/bin o ~/.cargo/bin).
  --install-dir <DIR>    Directorio de instalación personalizado.
  --profile <release|debug> Perfil de compilación de Cargo (default: release).
  --skip-frontend        Omite la compilación del frontend Svelte si dist ya existe.
  --skip-npm-install     Omite 'npm ci' / 'npm install'.
  --clean                Limpia artefactos previos antes de compilar (cargo clean + rm dist).
  --check                Ejecuta verificación smoke test tras el build.
  -h, --help             Muestra esta ayuda.

Ejemplos:
  ./build.sh
  ./build.sh --install
  ./build.sh --install --check
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install|-install)
            INSTALL=true
            shift
            ;;
        --install-dir|-install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --profile|-profile)
            PROFILE="$2"
            shift 2
            ;;
        --skip-frontend|-skip-frontend)
            SKIP_FRONTEND=true
            shift
            ;;
        --skip-npm-install|-skip-npm-install)
            SKIP_NPM_INSTALL=true
            shift
            ;;
        --clean|-clean)
            CLEAN=true
            shift
            ;;
        --check|-check|--smoke-test)
            CHECK=true
            shift
            ;;
        -h|--help|-help)
            print_help
            exit 0
            ;;
        *)
            echo "Opción desconocida: $1" >&2
            print_help >&2
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"
UI_DIR="$REPO_ROOT/ui/decision"
TARGET_PROFILE_DIR="$PROFILE"

EXE_SUFFIX=""
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
    EXE_SUFFIX=".exe"
fi

ARC_EXE="arc${EXE_SUFFIX}"
HOST_EXE="arc-decision-ui-host${EXE_SUFFIX}"
TARGET_BIN_DIR="$REPO_ROOT/target/$TARGET_PROFILE_DIR"
ARC_TARGET="$TARGET_BIN_DIR/$ARC_EXE"
HOST_TARGET="$TARGET_BIN_DIR/$HOST_EXE"

log_step() {
    echo -e "\n\033[1;36m=== $1 ===\033[0m"
}

log_ok() {
    echo -e "  \033[1;32m[OK]\033[0m $1"
}

log_warn() {
    echo -e "  \033[1;33m[WARN]\033[0m $1"
}

log_error() {
    echo -e "  \033[1;31m[ERROR]\033[0m $1" >&2
}

# ------------------------------------------------------------------------------
# Paso 0: Verificaciones previas
# ------------------------------------------------------------------------------
log_step "Paso 0: Verificaciones previas del entorno"

command -v cargo >/dev/null 2>&1 || { log_error "cargo no está en PATH"; exit 1; }
command -v rustc >/dev/null 2>&1 || { log_error "rustc no está en PATH"; exit 1; }
log_ok "Rust: $(rustc --version)"

if [[ "$SKIP_FRONTEND" == false ]]; then
    command -v node >/dev/null 2>&1 || { log_error "node no está en PATH"; exit 1; }
    command -v npm >/dev/null 2>&1 || { log_error "npm no está en PATH"; exit 1; }
    log_ok "Node.js: $(node --version), npm: $(npm --version)"
fi

[[ -f "$REPO_ROOT/Cargo.toml" ]] || { log_error "Cargo.toml no encontrado en $REPO_ROOT"; exit 1; }
[[ -f "$UI_DIR/package.json" ]] || { log_error "package.json no encontrado en $UI_DIR"; exit 1; }

# ------------------------------------------------------------------------------
# Limpieza opcional
# ------------------------------------------------------------------------------
if [[ "$CLEAN" == true ]]; then
    log_step "Limpieza de artefactos previos (--clean)"
    (cd "$REPO_ROOT" && cargo clean)
    if [[ -d "$UI_DIR/dist" ]]; then
        rm -rf "$UI_DIR/dist"
        log_ok "Directorio $UI_DIR/dist eliminado."
    fi
fi

# ------------------------------------------------------------------------------
# Paso 1: Frontend
# ------------------------------------------------------------------------------
if [[ "$SKIP_FRONTEND" == false ]]; then
    log_step "Paso 1: Compilación del Frontend Svelte/Vite"
    if [[ ! -d "$UI_DIR/node_modules" && "$SKIP_NPM_INSTALL" == false ]]; then
        echo "  Instalando dependencias de npm en ui/decision..."
        (cd "$UI_DIR" && (npm ci --ignore-scripts || npm install --ignore-scripts))
        log_ok "Dependencias de npm instaladas."
    fi

    echo "  Ejecutando 'npm run build'..."
    (cd "$UI_DIR" && npm run build)

    [[ -f "$UI_DIR/dist/index.html" ]] || { log_error "dist/index.html no generado"; exit 1; }
    log_ok "Frontend compilado exitosamente en ui/decision/dist."
else
    log_step "Paso 1: Frontend omitido (--skip-frontend)"
    [[ -f "$UI_DIR/dist/index.html" ]] || { log_error "No existe $UI_DIR/dist/index.html. No se puede omitir el frontend."; exit 1; }
    log_ok "Usando assets de frontend preexistentes."
fi

# ------------------------------------------------------------------------------
# Paso 2: Decision UI Host sidecar
# ------------------------------------------------------------------------------
log_step "Paso 2: Compilación de Decision UI Host sidecar ($HOST_EXE)"

CARGO_RELEASE_FLAG=""
if [[ "$PROFILE" == "release" ]]; then
    CARGO_RELEASE_FLAG="--release"
fi

echo "  Compilando arc-decision-ui-host..."
(cd "$REPO_ROOT" && cargo build --manifest-path Cargo.toml $CARGO_RELEASE_FLAG -p arc-decision-ui-host --features arc-decision-ui-host/custom-protocol)

[[ -f "$HOST_TARGET" ]] || { log_error "Binario sidecar no encontrado en $HOST_TARGET"; exit 1; }
log_ok "Decision UI Host generado en $HOST_TARGET"

# ------------------------------------------------------------------------------
# Paso 3: Arc Core CLI
# ------------------------------------------------------------------------------
log_step "Paso 3: Compilación de Arc Core CLI ($ARC_EXE)"

echo "  Compilando arc..."
(cd "$REPO_ROOT" && cargo build --manifest-path Cargo.toml $CARGO_RELEASE_FLAG -p arc --bin arc)

[[ -f "$ARC_TARGET" ]] || { log_error "Binario arc no encontrado en $ARC_TARGET"; exit 1; }
log_ok "Arc Core CLI generado en $ARC_TARGET"
log_ok "Ambos binarios son hermanos co-localizados en $TARGET_BIN_DIR"

# ------------------------------------------------------------------------------
# Paso 4: Instalación
# ------------------------------------------------------------------------------
if [[ "$INSTALL" == true ]]; then
    log_step "Paso 4: Instalación y Co-localización de Binarios Hermanos (--install)"

    DEST_DIR=""
    if [[ -n "$INSTALL_DIR" ]]; then
        DEST_DIR="$(cd "$INSTALL_DIR" 2>/dev/null && pwd || echo "$INSTALL_DIR")"
    elif [[ -n "${CARGO_HOME:-}" ]]; then
        DEST_DIR="$CARGO_HOME/bin"
    else
        DEST_DIR="$HOME/.cargo/bin"
    fi

    mkdir -p "$DEST_DIR"
    echo "  Directorio de instalación: $DEST_DIR"

    echo "  Ejecutando cargo install --path . --force..."
    INSTALL_CMD=(cargo install --path . --force)
    if [[ -n "$INSTALL_DIR" ]]; then
        INSTALL_CMD+=(--root "$(dirname "$DEST_DIR")")
    fi
    (cd "$REPO_ROOT" && "${INSTALL_CMD[@]}")

    echo "  Copiando sidecar hermano $HOST_EXE a $DEST_DIR..."
    cp -f "$HOST_TARGET" "$DEST_DIR/$HOST_EXE"

    [[ -f "$DEST_DIR/$ARC_EXE" ]] || { log_error "Falta $ARC_EXE en $DEST_DIR"; exit 1; }
    [[ -f "$DEST_DIR/$HOST_EXE" ]] || { log_error "Falta $HOST_EXE en $DEST_DIR"; exit 1; }

    log_ok "Instalación completada exitosamente en $DEST_DIR"
fi

# ------------------------------------------------------------------------------
# Paso 5: Verificación
# ------------------------------------------------------------------------------
if [[ "$CHECK" == true ]]; then
    log_step "Paso 5: Verificación y Smoke Test (--check)"

    TEST_ARC="$ARC_TARGET"
    if [[ "$INSTALL" == true ]]; then
        TEST_ARC="$DEST_DIR/$ARC_EXE"
    fi

    echo "  Probando '$TEST_ARC --version'..."
    VER_OUT="$("$TEST_ARC" --version)"
    log_ok "Versión verificada: $VER_OUT"

    SIBLING_DIR="$(dirname "$TEST_ARC")"
    [[ -f "$SIBLING_DIR/$HOST_EXE" ]] || { log_error "El sidecar hermano $HOST_EXE no existe en $SIBLING_DIR"; exit 1; }
    log_ok "Resolución de sidecar hermano confirmada en $SIBLING_DIR/$HOST_EXE"
fi

log_step "Build Completado con Éxito"
log_ok "Binarios disponibles en $TARGET_BIN_DIR"
if [[ "$INSTALL" == true ]]; then
    log_ok "Instalados en PATH: $DEST_DIR"
fi
exit 0
