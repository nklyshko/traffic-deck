// Entry compiled by frida-compile into java-bridge.js, a self-contained bundle of
// frida-java-bridge. capture.py prepends that bundle to legacy unpinning scripts when
// running under Frida >= 17, where the `Java` global was removed from the runtime.
// Idempotent: leaves Frida <= 16's built-in `Java` untouched.
import Java from 'frida-java-bridge';

if (typeof globalThis.Java === 'undefined') {
  globalThis.Java = Java;
}
