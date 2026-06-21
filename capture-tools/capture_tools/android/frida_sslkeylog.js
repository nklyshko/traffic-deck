'use strict';

// Frida agent: dump TLS secrets in NSS key-log format by hooking BoringSSL's
// SSL_CTX_set_keylog_callback (Android's libssl). Each secret line is delivered to
// the Python host via send({type:'keylog', line}); diagnostics via send({type:'log'}).
// Adapted from parsing_reversing_pipeline/sniff-server/assets/frida_sslkeylog.js.

function log(message) {
  try { send({ type: 'log', message: String(message) }); } catch (_) {}
}

function emitKey(line) {
  if (!line || line.length === 0) return;
  try { send({ type: 'keylog', line: line }); } catch (_) {}
}

function findExport(name) {
  try {
    if (typeof Module.getGlobalExportByName === 'function') {
      const p = Module.getGlobalExportByName(name);
      if (p && !p.isNull()) return p;
    }
  } catch (_) {}
  const modules = ['libssl.so', 'libboringssl.so', 'libconscrypt_jni.so'];
  for (let i = 0; i < modules.length; i++) {
    try {
      const mod = Process.findModuleByName(modules[i]);
      if (!mod) continue;
      const p = mod.findExportByName(name);
      if (p && !p.isNull()) return p;
    } catch (_) {}
  }
  return null;
}

function install() {
  const setKeylogCallbackPtr = findExport('SSL_CTX_set_keylog_callback');
  if (!setKeylogCallbackPtr) {
    log('SSL_CTX_set_keylog_callback not found (no BoringSSL?)');
    return;
  }
  const setKeylogCallback = new NativeFunction(setKeylogCallbackPtr, 'void', ['pointer', 'pointer']);

  const callback = new NativeCallback(function (_ssl, linePtr) {
    try { emitKey(linePtr.readCString()); } catch (e) { log('callback read failed: ' + e); }
  }, 'void', ['pointer', 'pointer']);
  globalThis.__sniffSslKeylogCallback = callback; // keep alive

  function attach(ctx) {
    try { if (ctx && !ctx.isNull()) setKeylogCallback(ctx, callback); }
    catch (e) { log('set callback failed: ' + e); }
  }

  const sslCtxNew = findExport('SSL_CTX_new');
  if (sslCtxNew) {
    Interceptor.attach(sslCtxNew, { onLeave(retval) { attach(retval); } });
    log('hooked SSL_CTX_new');
  }
  const sslNew = findExport('SSL_new');
  if (sslNew) {
    Interceptor.attach(sslNew, { onEnter(args) { attach(args[0]); } });
    log('hooked SSL_new');
  }
}

setImmediate(install);
