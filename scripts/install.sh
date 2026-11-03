#!/usr/bin/env bash
# Freeze this tree into a self-contained prefix (ADR-0017). Everything risky runs before the
# old prefix is touched: venvs hold absolute paths, so they must be built in place, and a
# failed build shouldn't cost a working install.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Absolute, and resolved before the cd below: the venvs and the link in BINDIR keep these
# paths, so a relative one would point nowhere. No trailing slash, so "$PREFIX.old.*" is a
# sibling of the prefix rather than a directory inside it.
abspath() { [[ "$1" = /* ]] && echo "${1%/}" || echo "$PWD/${1%/}"; }
PREFIX="$(abspath "${PREFIX:-$HOME/.local/share/trafficdeck}")"
BINDIR="$(abspath "${BINDIR:-$HOME/.local/bin}")"
DEFAULT_COMPONENTS="capture_chrome capture_firefox capture_mitmproxy capture_android tui mcp"
[[ "$(uname -s)" = Darwin ]] && DEFAULT_COMPONENTS+=" capture_pktap"
COMPONENTS="${COMPONENTS:-$DEFAULT_COMPONENTS}"
# Not PYTHON_VERSION: that name is commonly set already (Python's Docker images, CI), and
# would silently pick the interpreter.
INSTALL_PYTHON="${INSTALL_PYTHON:-3.12}"

die() { echo "install: $*" >&2; exit 1; }

cd "$ROOT"
dirty=false
if [[ -n "$(git status --porcelain)" ]]; then
  [[ "${ALLOW_DIRTY:-}" = 1 ]] || die "the tree has uncommitted changes, so the recorded commit wouldn't describe the install; commit, or pass ALLOW_DIRTY=1"
  dirty=true
fi
# .incomplete marks a prefix a failed install left behind, which is ours to replace.
if [[ -e "$PREFIX" && ! -e "$PREFIX/install.toml" && ! -e "$PREFIX/.incomplete" && -n "$(ls -A "$PREFIX")" ]]; then
  die "$PREFIX exists and is not an install; refusing to replace it"
fi

commit="$(git rev-parse HEAD)"
version="0.0.0+g${commit:0:12}"
$dirty && version+=".dirty"
branch="$(git rev-parse --abbrev-ref HEAD)"
remote_name="$(git config "branch.$branch.remote" || true)"
remote_url=""
# "." is a branch tracking another local branch: there is no remote to check for updates.
[[ -n "$remote_name" && "$remote_name" != . ]] && remote_url="$(git remote get-url "$remote_name")"
merge="$(git config "branch.$branch.merge" || true)"

project_dir() {
  case "$1" in
    capture_*) echo "capture/$1" ;;
    proto) echo "proto/python" ;;
    *) echo "$1" ;;
  esac
}

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

# A copy, not the tree itself: versions are stamped into pyproject.toml, and only files git
# would commit may reach a wheel.
git ls-files -z -co --exclude-standard | while IFS= read -r -d '' f; do
  [[ -f "$f" ]] || continue
  mkdir -p "$stage/src/$(dirname "$f")"
  cp -p "$f" "$stage/src/$f"
done

mkdir -p "$stage/out/wheels" "$stage/out/requirements" "$stage/out/bin"
# Every component needs the stubs and every capture app the SDK, so a filter can't leave
# them out. pktap is built on capture_chrome's pickers, so it brings that wheel along.
builds="proto capture_sdk $COMPONENTS"
[[ " $COMPONENTS " = *" capture_pktap "* && " $COMPONENTS " != *" capture_chrome "* ]] && builds+=" capture_chrome"
for c in $builds; do
  dir="$stage/src/$(project_dir "$c")"
  [[ -d "$dir" ]] || die "unknown component: $c"
  sed -i.orig "s/^version = \"0\.0\.0\"$/version = \"$version\"/" "$dir/pyproject.toml"
  rm "$dir/pyproject.toml.orig"
done
for c in $builds; do
  dir="$stage/src/$(project_dir "$c")"
  echo "building $c"
  uv build --quiet --wheel "$dir" --out-dir "$stage/out/wheels"
  # --no-emit-local: first-party packages are wheels here, and the lock names them by a path
  # that only exists in a checkout.
  uv export --quiet --frozen --no-dev --no-emit-project --no-emit-local --no-header \
    --project "$dir" -o "$stage/out/requirements/$c.txt" >/dev/null
done
(cd gateway && go build -o "$stage/out/bin/trafficdeck" ./cmd/gateway)

# A throwaway install of every third-party requirement fills uv's cache, so the real one
# below runs --offline and a network failure can't strike after the old prefix is gone.
for c in $COMPONENTS; do
  echo "fetching $c"
  uv venv --quiet --python "$INSTALL_PYTHON" "$stage/venvs/$c"
  uv pip install --quiet --python "$stage/venvs/$c/bin/python" -r "$stage/out/requirements/$c.txt"
done

# Moved aside before it is deleted: a removal that failed partway (root-owned files from an
# older pktap run) would leave a prefix with neither install.toml nor .incomplete, which every
# later install would refuse to replace.
if [[ -e "$PREFIX" ]]; then
  old="$(mktemp -d "$PREFIX.old.XXXXXX")"
  mv "$PREFIX" "$old/"
  rm -rf "$old" 2>/dev/null || echo "install: could not fully remove the old install; delete $old with sudo" >&2
fi
mkdir -p "$PREFIX/venvs" "$PREFIX/libexec"
touch "$PREFIX/.incomplete"
cp -R "$stage/out/." "$PREFIX/"

# --compile-bytecode: pktap runs under sudo, and a root interpreter would otherwise write
# root-owned __pycache__ into the prefix, which the next install could not remove.
for c in $COMPONENTS; do
  env="$PREFIX/venvs/$c"
  echo "installing $c"
  uv venv --quiet --offline --python "$INSTALL_PYTHON" "$env"
  uv pip install --quiet --offline --compile-bytecode --python "$env/bin/python" \
    -r "$PREFIX/requirements/$c.txt"
  pkgs=("trafficdeck-${c//_/-}" trafficdeck-proto)
  [[ "$c" = capture_* ]] && pkgs+=(trafficdeck-capture-sdk)
  [[ "$c" = capture_pktap ]] && pkgs+=(trafficdeck-capture-chrome)
  # --no-index, or a same-named package on PyPI could stand in for a first-party wheel.
  uv pip install --quiet --compile-bytecode --python "$env/bin/python" --no-deps --no-index \
    --find-links "$PREFIX/wheels" "${pkgs[@]}"
  script="trafficdeck-${c//_/-}"
  ln -s "../venvs/$c/bin/$script" "$PREFIX/libexec/$script"
done

# A TOML basic string: a quote or backslash in a path or URL would otherwise break the file.
toml_str() { local s="${1//\\/\\\\}"; s="${s//\"/\\\"}"; printf '"%s"' "$s"; }

# Written last: its presence is what makes this directory an install.
cat > "$PREFIX/install.toml" <<EOF
commit = "$commit"
dirty = $dirty
source_dir = $(toml_str "$ROOT")
remote = $(toml_str "$remote_url")
branch = $(toml_str "${merge#refs/heads/}")
date = "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
EOF
rm "$PREFIX/.incomplete"

mkdir -p "$BINDIR"
ln -sf "$PREFIX/bin/trafficdeck" "$BINDIR/trafficdeck"
echo "installed ${commit:0:12} into $PREFIX"
