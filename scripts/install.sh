#!/usr/bin/env bash
# Freeze this tree into a self-contained prefix (ADR-0017). Everything risky runs before the
# old prefix is touched: venvs hold absolute paths, so they must be built in place, and a
# failed build shouldn't cost a working install.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${PREFIX:-$HOME/.local/share/trafficdeck}"
BINDIR="${BINDIR:-$HOME/.local/bin}"
DEFAULT_COMPONENTS="capture_chrome capture_firefox capture_mitmproxy capture_android tui mcp"
[[ "$(uname -s)" = Darwin ]] && DEFAULT_COMPONENTS+=" capture_pktap"
COMPONENTS="${COMPONENTS:-$DEFAULT_COMPONENTS}"
PYTHON_VERSION="${PYTHON_VERSION:-3.12}"

die() { echo "install: $*" >&2; exit 1; }

cd "$ROOT"
dirty=false
if [[ -n "$(git status --porcelain)" ]]; then
  [[ "${ALLOW_DIRTY:-}" = 1 ]] || die "the tree has uncommitted changes, so the recorded commit wouldn't describe the install; commit, or pass ALLOW_DIRTY=1"
  dirty=true
fi
if [[ -e "$PREFIX" && ! -e "$PREFIX/install.toml" && -n "$(ls -A "$PREFIX")" ]]; then
  die "$PREFIX exists and is not an install; refusing to replace it"
fi

commit="$(git rev-parse HEAD)"
version="0.0.0+g${commit:0:12}"
$dirty && version+=".dirty"
branch="$(git rev-parse --abbrev-ref HEAD)"
remote_name="$(git config "branch.$branch.remote" || true)"
remote_url=""
[[ -n "$remote_name" ]] && remote_url="$(git remote get-url "$remote_name")"
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
# them out.
for c in proto capture_sdk $COMPONENTS; do
  dir="$stage/src/$(project_dir "$c")"
  [[ -d "$dir" ]] || die "unknown component: $c"
  sed -i.orig "s/^version = \"0\.0\.0\"$/version = \"$version\"/" "$dir/pyproject.toml"
  rm "$dir/pyproject.toml.orig"
done
for c in proto capture_sdk $COMPONENTS; do
  dir="$stage/src/$(project_dir "$c")"
  echo "building $c"
  uv build --quiet --wheel "$dir" --out-dir "$stage/out/wheels"
  # --no-emit-package: these are first-party wheels, and the lock names them by a path that
  # only exists in a checkout.
  uv export --quiet --frozen --no-dev --no-emit-project \
    --no-emit-package trafficdeck-capture-sdk --no-emit-package trafficdeck-proto --no-header \
    --project "$dir" -o "$stage/out/requirements/$c.txt" >/dev/null
done
(cd gateway && go build -o "$stage/out/bin/trafficdeck" ./cmd/gateway)

rm -rf "$PREFIX"
mkdir -p "$PREFIX/venvs" "$PREFIX/libexec"
cp -R "$stage/out/." "$PREFIX/"

for c in $COMPONENTS; do
  env="$PREFIX/venvs/$c"
  echo "installing $c"
  uv venv --quiet --python "$PYTHON_VERSION" "$env"
  uv pip install --quiet --python "$env/bin/python" -r "$PREFIX/requirements/$c.txt"
  pkgs=("trafficdeck-${c//_/-}" trafficdeck-proto)
  [[ "$c" = capture_* ]] && pkgs+=(trafficdeck-capture-sdk)
  # --no-index, or a same-named package on PyPI could stand in for a first-party wheel.
  uv pip install --quiet --python "$env/bin/python" --no-deps --no-index \
    --find-links "$PREFIX/wheels" "${pkgs[@]}"
  script="trafficdeck-${c//_/-}"
  ln -s "../venvs/$c/bin/$script" "$PREFIX/libexec/$script"
done

# Written last: its presence is what makes this directory an install.
cat > "$PREFIX/install.toml" <<EOF
commit = "$commit"
dirty = $dirty
source_dir = "$ROOT"
remote = "$remote_url"
branch = "${merge#refs/heads/}"
date = "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
EOF

mkdir -p "$BINDIR"
ln -sf "$PREFIX/bin/trafficdeck" "$BINDIR/trafficdeck"
echo "installed ${commit:0:12} into $PREFIX"
