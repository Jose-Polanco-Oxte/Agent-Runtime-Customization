#!/usr/bin/env sh
# ==============================================================================
# Arc Prebuilt Release Installer for Linux and macOS (install.sh)
# License: MIT OR Apache-2.0
# ==============================================================================
set -eu

VERSION="${ARC_VERSION:-}"
INSTALL_DIR="${ARC_INSTALL_DIR:-}"
BASE_URL="${ARC_RELEASE_BASE_URL:-}"
ARCHIVE_PATH=""
CHECKSUMS_PATH=""
TARGET=""
NO_MODIFY_PATH=0

print_usage() {
    cat << 'EOF'
Arc Prebuilt Release Installer for Linux and macOS (install.sh)
License: MIT OR Apache-2.0

Usage:
  ./install.sh [options]

Options:
  --version <version>       Version of Arc to install (env: ARC_VERSION, default: 1.0.0)
  --install-dir <path>      Target bin directory (env: ARC_INSTALL_DIR, default: $HOME/.arc/bin)
  --base-url <url>          Base URL for release assets (env: ARC_RELEASE_BASE_URL)
  --archive <path>          Local path to release .tar.gz archive (offline/test mode)
  --checksums <path>        Local path to SHA256SUMS file (offline/test mode)
  --target <triple>         Explicit target triple override (e.g. x86_64-unknown-linux-gnu)
  --no-modify-path          Do not modify shell profile files; only print PATH instructions
  -h, --help                Display this help message and exit 0

Examples:
  ./install.sh
  ./install.sh --version 1.0.0 --install-dir "$HOME/.arc/bin" --no-modify-path
  ./install.sh --archive ./arc-v1.0.0-x86_64-unknown-linux-gnu.tar.gz --checksums ./SHA256SUMS
EOF
}

log_error() {
    printf 'Error: %s\n' "$*" >&2
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            print_usage
            exit 0
            ;;
        --version)
            if [ $# -lt 2 ]; then
                log_error "--version requires a value"
                exit 1
            fi
            VERSION="$2"
            shift 2
            ;;
        --version=*)
            VERSION="${1#*=}"
            shift
            ;;
        --install-dir)
            if [ $# -lt 2 ]; then
                log_error "--install-dir requires a value"
                exit 1
            fi
            INSTALL_DIR="$2"
            shift 2
            ;;
        --install-dir=*)
            INSTALL_DIR="${1#*=}"
            shift
            ;;
        --base-url)
            if [ $# -lt 2 ]; then
                log_error "--base-url requires a value"
                exit 1
            fi
            BASE_URL="$2"
            shift 2
            ;;
        --base-url=*)
            BASE_URL="${1#*=}"
            shift
            ;;
        --archive|--archive-path)
            if [ $# -lt 2 ]; then
                log_error "$1 requires a value"
                exit 1
            fi
            ARCHIVE_PATH="$2"
            shift 2
            ;;
        --archive=*|--archive-path=*)
            ARCHIVE_PATH="${1#*=}"
            shift
            ;;
        --checksums|--checksum-path)
            if [ $# -lt 2 ]; then
                log_error "$1 requires a value"
                exit 1
            fi
            CHECKSUMS_PATH="$2"
            shift 2
            ;;
        --checksums=*|--checksum-path=*)
            CHECKSUMS_PATH="${1#*=}"
            shift
            ;;
        --target)
            if [ $# -lt 2 ]; then
                log_error "--target requires a value"
                exit 1
            fi
            TARGET="$2"
            shift 2
            ;;
        --target=*)
            TARGET="${1#*=}"
            shift
            ;;
        --no-modify-path)
            NO_MODIFY_PATH=1
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            print_usage >&2
            exit 1
            ;;
    esac
done

# 1. Resolve and normalize version
if [ -z "$VERSION" ]; then
    VERSION="1.0.0"
fi
case "$VERSION" in
    v*|V*)
        VERSION="${VERSION#?}"
        ;;
esac
if [ -z "$VERSION" ]; then
    log_error "Invalid empty version specified."
    exit 1
fi

# 2. Resolve installation directory
if [ -z "$INSTALL_DIR" ]; then
    if [ -z "${HOME:-}" ]; then
        log_error "HOME is not set and --install-dir / ARC_INSTALL_DIR was not provided."
        exit 1
    fi
    INSTALL_DIR="${HOME%/}/.arc/bin"
fi

# 3. Detect host OS and CPU architecture when --target is not provided
resolve_uname_bin() {
    old_ifs="$IFS"
    IFS=":"
    for path_dir in ${PATH:-}; do
        case "$path_dir" in
            ""|/usr/bin|/bin|/mingw64/bin|/usr/local/bin)
                continue
                ;;
        esac
        if [ -f "${path_dir}/uname" ] && [ -x "${path_dir}/uname" ]; then
            IFS="$old_ifs"
            printf '%s\n' "${path_dir}/uname"
            return 0
        fi
    done
    IFS="$old_ifs"
    printf 'uname\n'
}

detect_target() {
    uname_cmd="$(resolve_uname_bin)"
    os_name="$("$uname_cmd" -s 2>/dev/null || echo unknown)"
    arch_name="$("$uname_cmd" -m 2>/dev/null || echo unknown)"

    case "$os_name" in
        Linux)
            case "$arch_name" in
                x86_64|amd64)
                    printf 'x86_64-unknown-linux-gnu\n'
                    return 0
                    ;;
                *)
                    log_error "Unsupported Linux architecture: ${arch_name}. Supported: x86_64."
                    return 1
                    ;;
            esac
            ;;
        Darwin)
            case "$arch_name" in
                arm64|aarch64)
                    printf 'aarch64-apple-darwin\n'
                    return 0
                    ;;
                x86_64|amd64)
                    printf 'x86_64-apple-darwin\n'
                    return 0
                    ;;
                *)
                    log_error "Unsupported macOS architecture: ${arch_name}. Supported: arm64/aarch64, x86_64."
                    return 1
                    ;;
            esac
            ;;
        *)
            log_error "Unsupported operating system: ${os_name} (${arch_name}). Supported: Linux (x86_64), Darwin (arm64/aarch64, x86_64)."
            return 1
            ;;
    esac
}

if [ -z "$TARGET" ]; then
    TARGET="$(detect_target)" || exit 1
fi

CANONICAL_ARCHIVE_NAME="arc-v${VERSION}-${TARGET}.tar.gz"

# 4. Resolve Base URL
if [ -z "$BASE_URL" ]; then
    REPO_SLUG="${ARC_GITHUB_REPO:-Tonybs03/Agent-Runtime-Customization}"
    BASE_URL="https://github.com/${REPO_SLUG}/releases/download/v${VERSION}"
fi
BASE_URL="${BASE_URL%/}"

# 5. Create temporary staging directory
STAGING_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t arc-install)"
cleanup() {
    if [ -n "${STAGING_DIR:-}" ] && [ -d "$STAGING_DIR" ]; then
        rm -rf "$STAGING_DIR"
    fi
}
trap cleanup EXIT INT TERM

download_file() {
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
    else
        log_error "Neither curl nor wget was found in PATH to download ${url}."
        return 1
    fi
}

# 6. Acquire release archive and SHA256SUMS
if [ -n "$ARCHIVE_PATH" ]; then
    if [ ! -f "$ARCHIVE_PATH" ]; then
        log_error "Specified archive file does not exist: ${ARCHIVE_PATH}"
        exit 1
    fi
    LOCAL_ARCHIVE="$ARCHIVE_PATH"
    ARCHIVE_FILENAME="$(basename "$LOCAL_ARCHIVE")"
else
    LOCAL_ARCHIVE="${STAGING_DIR}/${CANONICAL_ARCHIVE_NAME}"
    ARCHIVE_FILENAME="$CANONICAL_ARCHIVE_NAME"
    ARCHIVE_URL="${BASE_URL}/${CANONICAL_ARCHIVE_NAME}"
    printf 'Downloading %s ...\n' "$ARCHIVE_URL"
    download_file "$ARCHIVE_URL" "$LOCAL_ARCHIVE" || exit 1
fi

if [ -n "$CHECKSUMS_PATH" ]; then
    if [ ! -f "$CHECKSUMS_PATH" ]; then
        log_error "Specified checksums file does not exist: ${CHECKSUMS_PATH}"
        exit 1
    fi
    LOCAL_CHECKSUMS="$CHECKSUMS_PATH"
else
    LOCAL_CHECKSUMS="${STAGING_DIR}/SHA256SUMS"
    CHECKSUMS_URL="${BASE_URL}/SHA256SUMS"
    printf 'Downloading %s ...\n' "$CHECKSUMS_URL"
    download_file "$CHECKSUMS_URL" "$LOCAL_CHECKSUMS" || exit 1
fi

# 7. Verify SHA-256 checksum BEFORE extraction
compute_sha256() {
    file_to_hash="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file_to_hash" | awk '{print tolower($1)}'
        return 0
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file_to_hash" | awk '{print tolower($1)}'
        return 0
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$file_to_hash" | awk '{print tolower($NF)}'
        return 0
    else
        log_error "Neither sha256sum, shasum, nor openssl is available for SHA-256 verification."
        return 1
    fi
}

resolve_expected_sha256() {
    sums_file="$1"
    cand_primary="$2"
    cand_secondary="$3"

    awk -v c1="$cand_primary" -v c2="$cand_secondary" '
        {
            sub(/\r$/, "")
            if ($0 ~ /^[[:space:]]*$/ || $0 ~ /^[[:space:]]*#/) {
                next
            }
            hash = tolower($1)
            file = $2
            sub(/^\*/, "", file)
            gsub(/^.*\//, "", file)
            gsub(/^.*\\/, "", file)
            if (hash ~ /^[0-9a-f]{64}$/ && (file == c1 || file == c2)) {
                print hash
                exit 0
            }
        }
    ' "$sums_file"
}

EXPECTED_HASH="$(resolve_expected_sha256 "$LOCAL_CHECKSUMS" "$ARCHIVE_FILENAME" "$CANONICAL_ARCHIVE_NAME")"
if [ -z "$EXPECTED_HASH" ]; then
    log_error "No matching SHA-256 entry found in '${LOCAL_CHECKSUMS}' for '${ARCHIVE_FILENAME}' (or '${CANONICAL_ARCHIVE_NAME}')."
    exit 1
fi

ACTUAL_HASH="$(compute_sha256 "$LOCAL_ARCHIVE")" || exit 1
if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
    log_error "SHA-256 checksum mismatch for '${ARCHIVE_FILENAME}': expected ${EXPECTED_HASH}, got ${ACTUAL_HASH}. Aborting before extraction."
    exit 1
fi
printf 'Verified SHA-256 checksum for %s (%s)\n' "$ARCHIVE_FILENAME" "$ACTUAL_HASH"

# 8. Extract archive into temporary directory and validate contents before installing
EXTRACT_DIR="${STAGING_DIR}/extracted"
mkdir -p "$EXTRACT_DIR"
tar -xzf - -C "$EXTRACT_DIR" < "$LOCAL_ARCHIVE"

find_extracted_file() {
    root_dir="$1"
    target_name="$2"
    if [ -f "${root_dir}/${target_name}" ]; then
        printf '%s\n' "${root_dir}/${target_name}"
        return 0
    fi
    found_path="$(find "$root_dir" -type f -name "$target_name" 2>/dev/null | head -n 1 || true)"
    if [ -n "$found_path" ] && [ -f "$found_path" ]; then
        printf '%s\n' "$found_path"
        return 0
    fi
    return 1
}

EXTRACTED_ARC="$(find_extracted_file "$EXTRACT_DIR" "arc")" || {
    log_error "Required binary 'arc' is missing from the release archive."
    exit 1
}

EXTRACTED_SIDECAR="$(find_extracted_file "$EXTRACT_DIR" "arc-decision-ui-host")" || {
    log_error "Required sibling binary 'arc-decision-ui-host' is missing from the release archive."
    exit 1
}

# 9. Install binaries side-by-side with 0755 permissions and license files
mkdir -p "$INSTALL_DIR"
RESOLVED_INSTALL_DIR="$(cd "$INSTALL_DIR" && pwd)"

INSTALLED_ARC="${RESOLVED_INSTALL_DIR}/arc"
INSTALLED_SIDECAR="${RESOLVED_INSTALL_DIR}/arc-decision-ui-host"

cp -f "$EXTRACTED_ARC" "$INSTALLED_ARC"
cp -f "$EXTRACTED_SIDECAR" "$INSTALLED_SIDECAR"
chmod 0755 "$INSTALLED_ARC" "$INSTALLED_SIDECAR"

for lic_name in LICENSE-MIT LICENSE-APACHE; do
    if extracted_lic="$(find_extracted_file "$EXTRACT_DIR" "$lic_name" 2>/dev/null)"; then
        cp -f "$extracted_lic" "${RESOLVED_INSTALL_DIR}/${lic_name}"
        chmod 0644 "${RESOLVED_INSTALL_DIR}/${lic_name}"
    fi
done

printf 'Arc v%s is dual-licensed under MIT OR Apache-2.0 (see LICENSE-MIT and LICENSE-APACHE).\n' "$VERSION"

# 10. Post-install verification (sibling co-location, executable bits, and arc --version)
if [ ! -f "$INSTALLED_ARC" ] || [ ! -x "$INSTALLED_ARC" ]; then
    log_error "Post-install verification failed: '${INSTALLED_ARC}' is missing or not executable."
    exit 1
fi

if [ ! -f "$INSTALLED_SIDECAR" ] || [ ! -x "$INSTALLED_SIDECAR" ]; then
    log_error "Post-install verification failed: sibling '${INSTALLED_SIDECAR}' is missing or not executable."
    exit 1
fi

ARC_PARENT_DIR="$(cd "$(dirname "$INSTALLED_ARC")" && pwd)"
SIDECAR_PARENT_DIR="$(cd "$(dirname "$INSTALLED_SIDECAR")" && pwd)"
if [ "$ARC_PARENT_DIR" != "$SIDECAR_PARENT_DIR" ]; then
    log_error "Post-install verification failed: 'arc' and 'arc-decision-ui-host' must be co-located in the same directory."
    exit 1
fi

VERSION_OUT="$("$INSTALLED_ARC" --version 2>&1)" || {
    log_error "Post-install verification failed: '${INSTALLED_ARC} --version' returned a non-zero exit code."
    exit 1
}
printf 'Verified binary execution: %s\n' "$VERSION_OUT"
printf 'Installed arc and arc-decision-ui-host side-by-side in: %s\n' "$RESOLVED_INSTALL_DIR"

# 11. Check PATH and print instructions if InstallDir is not on PATH
is_in_path=0
case ":${PATH:-}:" in
    *":${INSTALL_DIR}:"*|*":${RESOLVED_INSTALL_DIR}:"*)
        is_in_path=1
        ;;
esac

if [ "$is_in_path" -eq 0 ]; then
    old_ifs="$IFS"
    IFS=":"
    for path_entry in ${PATH:-}; do
        if [ -n "$path_entry" ] && [ -d "$path_entry" ]; then
            norm_entry="$(cd "$path_entry" 2>/dev/null && pwd || printf '%s' "$path_entry")"
            if [ "$norm_entry" = "$RESOLVED_INSTALL_DIR" ]; then
                is_in_path=1
                break
            fi
        fi
    done
    IFS="$old_ifs"
fi

if [ "$is_in_path" -eq 1 ]; then
    printf 'Install directory %s is already in PATH.\n' "$RESOLVED_INSTALL_DIR"
else
    printf 'Note: %s is not in your PATH.\n' "$RESOLVED_INSTALL_DIR"
    printf 'To add it to your PATH, add the following line to your shell profile (~/.profile, ~/.bashrc, or ~/.zshrc):\n'
    printf '  export PATH="%s:$PATH"\n' "$RESOLVED_INSTALL_DIR"
    if [ "$NO_MODIFY_PATH" -eq 1 ]; then
        printf '(Skipped modifying shell profile because --no-modify-path was set.)\n'
    fi
fi

exit 0
