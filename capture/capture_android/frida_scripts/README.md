# Standard Frida scripts

`*.js` files in this directory (SSL unpinning / pinning-bypass and similar) are
offered, by file name, on the unpinning/bypass step of the interactive Android
capture CLI (`trafficdeck-capture-android`). The step also lets you point at a custom
script path instead, or skip loading one. Override the directory with
`--scripts-dir <path>`.

The selected script loads alongside the always-on TLS keylog hook
(`../capture_android/frida_sslkeylog.js`); it does not replace it.

## Frida 17 compatibility (the `_bridge/` bundle)

Frida 17 removed the built-in `Java`/`ObjC` globals from the runtime, so legacy
scripts that call `Java.perform(...)` fail there with `ReferenceError: 'Java' is not
defined`. To keep these scripts working, `capture.py` prepends `_bridge/java-bridge.js`
— a plain-IIFE bundle of [`frida-java-bridge`](https://github.com/frida/frida-java-bridge)
that installs `globalThis.Java` — to any script that uses the `Java` global, but only
when running under Frida >= 17. On Frida <= 16 (which still provides `Java`) nothing is
prepended. Scripts that already bundle the bridge (contain `frida-java-bridge`) are
left untouched. So a script here works on both 16 and 17 without per-version copies.

### Rebuilding the bundle

`_bridge/java-bridge.js` is vendored (committed). Rebuild it after bumping
`frida-java-bridge`:

```bash
cd _bridge
npm install
npm run build   # esbuild -> java-bridge.js
```
