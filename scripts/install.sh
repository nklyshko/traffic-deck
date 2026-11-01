#!/usr/bin/env bash
# Freeze this tree into a self-contained prefix (ADR-0017). Everything risky runs before the
# old prefix is touched: venvs hold absolute paths, so they must be built in place, and a
# failed build shouldn't cost a working install.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
die() { echo "install: $*" >&2; exit 1; }

# Absolute, and resolved before the cd below: the venvs and the link in BINDIR keep these
# paths, so a relative one would point nowhere. Normalised, with no "." or ".." left and no
# trailing slash, so "$PREFIX.old.*" is a sibling of the prefix rather than inside it.
abspath() {
  local p="$1" out="" part parts
  [[ "$p" = /* ]] || p="$PWD/$p"
  IFS=/ read -r -a parts <<<"$p"
  for part in "${parts[@]}"; do
    case "$part" in
      "" | .) ;;
      ..) out="${out%/*}" ;;
      *) out+="/$part" ;;
    esac
  done
  echo "${out:-/}"
}
PREFIX="$(abspath "${PREFIX:-$HOME/.local/share/trafficdeck}")"
BINDIR="$(abspath "${BINDIR:-$HOME/.local/bin}")"
# Replacing the prefix deletes it, so it has to be a directory of its own.
case "$PREFIX" in
  / | "$(abspath "$HOME")" | "$(dirname "$(abspath "$HOME")")") die "PREFIX=$PREFIX would replace a directory that isn't the install's" ;;
esac
DEFAULT_COMPONENTS="capture_chrome capture_firefox capture_mitmproxy capture_android tui mcp"
[[ "$(uname -s)" = Darwin ]] && DEFAULT_COMPONENTS+=" capture_pktap"
COMPONENTS="${COMPONENTS:-$DEFAULT_COMPONENTS}"
# Not PYTHON_VERSION: that name is commonly set already (Python's Docker images, CI), and
# would silently pick the interpreter. An exact release, so two installs of one commit get
# the same interpreter rather than whichever 3.12 the local uv knows of. That needs a uv
# recent enough to know this release.
INSTALL_PYTHON="${INSTALL_PYTHON:-3.12.13}"
VIEWER="${VIEWER:-}"

# Checked first: `make build` tolerates a missing node with a stub page, but a frozen copy
# with a stub would only be discovered when someone opens it.
command -v npm >/dev/null || die "npm is needed to build the web UI (see mise.toml)"

# Recorded in a TOML string, and a bare `make install` is how an install updates: without
# carrying the choice over, an update would quietly put the viewer back.
if [[ -z "$VIEWER" && -f "$PREFIX/install.toml" ]]; then
  VIEWER="$(sed -n 's/^viewer = "\(.*\)"$/\1/p' "$PREFIX/install.toml")"
elif [[ "$VIEWER" = tui && " $COMPONENTS " != *" tui "* ]]; then
  die "VIEWER=tui, but COMPONENTS leaves the tui out"
fi
[[ "$VIEWER" != *[\"\\]* ]] || die "VIEWER can't contain a quote or a backslash"

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
# "." is a branch tracking another local branch, and a remote since removed leaves its name
# behind: either way there is no remote to check for updates.
[[ -n "$remote_name" && "$remote_name" != . ]] && remote_url="$(git remote get-url "$remote_name" 2>/dev/null || true)"
merge="$(git config "branch.$branch.merge" || true)"

project_dir() {
  case "$1" in
    capture_*) echo "capture/$1" ;;
    proto) echo "proto/python" ;;
    *) echo "$1" ;;
  esac
}

# The stage sits beside the prefix, not in /tmp: on the same filesystem it reaches the
# prefix by rename rather than a copy, uv can hardlink its cache into the throwaway venvs,
# and a tmpfs /tmp isn't asked to hold them in memory. A stage an install killed outright
# left behind is cleared first.
parent="$(dirname "$PREFIX")"
mkdir -p "$parent"
# One install per parent at a time: two would replace the same prefix, and the sweep below
# would delete a stage still in use. mkdir, because macOS has no flock(1). A lock whose
# process is gone was left by a killed install, and is taken over.
lock="$parent/.trafficdeck-install.lock"
if ! mkdir "$lock" 2>/dev/null; then
  holder="$(cat "$lock/pid" 2>/dev/null || true)"
  if [[ -n "$holder" ]] && kill -0 "$holder" 2>/dev/null; then
    die "another install into $parent is running (pid $holder)"
  fi
  rm -rf "$lock"
  mkdir "$lock" || die "another install into $parent took over $lock"
fi
echo $$ >"$lock/pid"
stage=""
trap 'rm -rf "$stage" "$lock"' EXIT
for d in "$parent"/.trafficdeck-stage.*; do
  [[ -d "$d" ]] && rm -rf "$d"
done
stage="$(mktemp -d "$parent/.trafficdeck-stage.XXXXXX")"

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
echo "building web"
mkdir -p "$stage/out/libexec"
(cd "$stage/src/web/ui" && npm ci --silent && npm run --silent build)
(cd "$stage/src/web" && go build -o "$stage/out/libexec/trafficdeck-web" .)

# The interpreter lives in the prefix too, or every venv would point at whichever Python was
# on PATH (mise's, Homebrew's), and removing that would break the install. uv's builds run
# from anywhere, so it is fetched into the stage and moved: only the versioned directory,
# since uv's minor-version link beside it is absolute. Its build configuration still names
# the stage, and is rewritten once it is in place.
echo "fetching Python $INSTALL_PYTHON"
uv python install --quiet --no-bin --install-dir "$stage/pythons" "$INSTALL_PYTHON" ||
  die "uv could not fetch Python $INSTALL_PYTHON: if it doesn't know that release, \`uv self update\` (or set INSTALL_PYTHON)"
pydir="$(find "$stage/pythons" -mindepth 1 -maxdepth 1 -type d -name 'cpython-*' | head -1)"
[[ -n "$pydir" ]] || die "uv installed no Python $INSTALL_PYTHON"
# Both spellings: on macOS the stage is under /var, a link to /private/var, and uv may have
# recorded either.
pydir_real="$(cd "$pydir" && pwd -P)"
mv "$pydir" "$stage/out/python"

# Android captures run under the frida matching the device's frida-server, so each version
# gets its own venv. frida_versions.py names them, so it stays the one place they are named.
frida_versions=""
if [[ " $COMPONENTS " = *" capture_android "* ]]; then
  frida_versions="$("$stage/out/python/bin/python3" -I -c \
    'import sys; sys.path.insert(0, sys.argv[1]); from capture_android import frida_versions as v; print(*v.SUPPORTED)' \
    "$stage/src/capture/capture_android")"
fi

# A throwaway install of every third-party requirement fills uv's cache, so the real one
# below runs --offline and a network failure can't strike after the old prefix is gone.
for c in $COMPONENTS; do
  echo "fetching $c"
  uv venv --quiet --python "$stage/out/python/bin/python3" "$stage/venvs/$c"
  uv pip install --quiet --python "$stage/venvs/$c/bin/python" -r "$stage/out/requirements/$c.txt"
done
for v in $frida_versions; do
  echo "fetching frida $v"
  uv pip install --quiet --python "$stage/venvs/capture_android/bin/python" "frida==$v"
done

# Moved aside before it is deleted: a removal that failed partway (root-owned files from an
# older pktap run) would leave a prefix with neither install.toml nor .incomplete, which every
# later install would refuse to replace.
if [[ -e "$PREFIX" ]]; then
  old="$(mktemp -d "$PREFIX.old.XXXXXX")"
  mv "$PREFIX" "$old/"
  rm -rf "$old" 2>/dev/null || echo "install: could not fully remove the old install; delete $old with sudo" >&2
fi
# Marked before the rename, so the prefix never exists without install.toml or .incomplete.
mkdir -p "$stage/out/venvs" "$stage/out/libexec"
touch "$stage/out/.incomplete"
mv "$stage/out" "$PREFIX"
# sysconfig, python3-config and the pkg-config files carry the directory uv installed into,
# which is the stage and about to be deleted: anything building a C extension against this
# Python would look for headers there.
{ grep -rlIF -e "$pydir" -e "$pydir_real" "$PREFIX/python" || true; } |
  "$PREFIX/python/bin/python3" -I -c '
import sys
new, *olds = sys.argv[1:]
for path in sys.stdin.read().splitlines():
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        text = f.read()
    for old in sorted(set(olds), key=len, reverse=True):
        text = text.replace(old, new)
    with open(path, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write(text)
' "$PREFIX/python" "$pydir_real" "$pydir"
# A few modules were compiled while the interpreter ran from the stage (at its fetched path
# or at out/python), and their bytecode names it. Removed, so compileall below writes them
# again.
stage_real="$(cd "$stage" && pwd -P)"
{ grep -rlaF --include='*.pyc' -e "$stage" -e "$stage_real" "$PREFIX/python" || true; } |
  while IFS= read -r f; do rm -f "$f"; done
# The standard library ships without bytecode, so whoever first imported a module would write
# it: under the root pktap, root-owned __pycache__ the next install could not remove. Compiled
# here, after the rewrite above changed some of those sources.
"$PREFIX/python/bin/python3" -m compileall -q -j0 "$PREFIX/python/lib" >/dev/null

# fill_venv ENV COMPONENT REQUIREMENT...: a venv on the prefix's Python with the third-party
# requirements, then the component's first-party wheels.
#
# --compile-bytecode: pktap runs under sudo, and a root interpreter would otherwise write
# root-owned __pycache__ into the prefix, which the next install could not remove.
#
# Built to survive the prefix being moved (an app bundle is copied wherever the user drops
# it): --relocatable makes console scripts find their interpreter beside themselves rather
# than by a shebang, and uv's absolute link to the base Python is replaced by a relative
# one. pyvenv.cfg still names the old home; Python finds its base through the link instead.
fill_venv() {
  local env="$1" c="$2"
  shift 2
  uv venv --quiet --offline --relocatable --python "$PREFIX/python/bin/python3" "$env"
  ln -sfn ../../../python/bin/python3 "$env/bin/python"
  uv pip install --quiet --offline --compile-bytecode --python "$env/bin/python" "$@"
  local pkgs=("trafficdeck-${c//_/-}" trafficdeck-proto)
  [[ "$c" = capture_* ]] && pkgs+=(trafficdeck-capture-sdk)
  [[ "$c" = capture_pktap ]] && pkgs+=(trafficdeck-capture-chrome)
  # --no-index, or a same-named package on PyPI could stand in for a first-party wheel.
  uv pip install --quiet --compile-bytecode --python "$env/bin/python" --no-deps --no-index \
    --find-links "$PREFIX/wheels" "${pkgs[@]}"
}

for c in $COMPONENTS; do
  env="$PREFIX/venvs/$c"
  echo "installing $c"
  fill_venv "$env" "$c" -r "$PREFIX/requirements/$c.txt"
  script="trafficdeck-${c//_/-}"
  ln -s "../venvs/$c/bin/$script" "$PREFIX/libexec/$script"
done
# The capture itself runs in these, never the CLI or source process: they hold the Android
# component plus the one frida a device needs (capture_android/frida_env.py).
for v in $frida_versions; do
  echo "installing frida $v"
  fill_venv "$PREFIX/venvs/android-frida-$v" capture_android \
    -r "$PREFIX/requirements/capture_android.txt" "frida==$v"
done

# A TOML basic string: a quote, backslash or line break in a path or URL would otherwise
# break the file. Other control characters have no business in either.
toml_str() {
  local s="${1//\\/\\\\}" nl=$'\n' cr=$'\r' tab=$'\t'
  s="${s//\"/\\\"}"
  s="${s//$nl/\\n}"
  s="${s//$cr/\\r}"
  s="${s//$tab/\\t}"
  [[ "$s" != *[[:cntrl:]]* ]] || die "a control character in $1 can't be recorded"
  printf '"%s"' "$s"
}

# Assigned first: a failure inside the heredoc below would not stop the script.
source_toml="$(toml_str "$ROOT")"
remote_toml="$(toml_str "$remote_url")"
branch_toml="$(toml_str "${merge#refs/heads/}")"

# Written last: its presence is what makes this directory an install.
cat > "$PREFIX/install.toml" <<EOF
commit = "$commit"
dirty = $dirty
source_dir = $source_toml
remote = $remote_toml
branch = $branch_toml
date = "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
viewer = "$VIEWER"
EOF
rm "$PREFIX/.incomplete"

mkdir -p "$BINDIR"
ln -sf "$PREFIX/bin/trafficdeck" "$BINDIR/trafficdeck"
echo "installed ${commit:0:12} into $PREFIX"
