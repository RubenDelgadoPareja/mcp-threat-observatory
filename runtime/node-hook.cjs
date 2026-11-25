#!/usr/bin/env node
/**
 * Behaviour observation hook.
 *
 * Loaded into the server process with `--require`. It writes newline-delimited
 * JSON to MCPOBS_BEHAVIOUR_LOG and NEVER to stdout, because for a stdio MCP
 * server stdout is the protocol channel.
 *
 * This is an observation mechanism, not a security boundary. It patches Node
 * APIs, so native addons, worker threads with their own loader, or a spawned
 * non-Node process can bypass it. Containment comes from running the whole
 * process tree in a network namespace.
 */
"use strict";

const LOG = process.env.MCPOBS_BEHAVIOUR_LOG;

function install() {
  const fs = require("node:fs");
  const net = require("node:net");
  const dns = require("node:dns");
  const cp = require("node:child_process");

  const CANARY = /CANARY-[0-9a-f]{16}/g;
  const SENSITIVE = [/\/\.ssh\//, /\/\.aws\//, /(^|\/)\.env$/, /\/\.npmrc$/];
  let writing = false;

  function emit(event) {
    if (!LOG || writing) return;
    writing = true;
    try {
      fs.appendFileSync(LOG, `${JSON.stringify({ at: new Date().toISOString(), ...event })}\n`);
    } catch {
      /* never break the server because the observer failed */
    } finally {
      writing = false;
    }
  }

  function canaryIdsIn(chunk) {
    let text = "";
    if (typeof chunk === "string") text = chunk;
    else if (Buffer.isBuffer(chunk)) text = chunk.toString("utf8");
    if (!text) return [];
    return [...new Set(text.match(CANARY) ?? [])];
  }

  function notePath(file) {
    let candidate = null;
    try {
      if (typeof file === "string") candidate = file;
      else if (file instanceof URL) candidate = file.pathname;
      else if (Buffer.isBuffer(file)) candidate = file.toString("utf8");
    } catch {
      return;
    }
    if (!candidate) return;
    if (SENSITIVE.some((pattern) => pattern.test(candidate))) {
      emit({ type: "fs.read", path: candidate });
    }
  }

  // ---- network destinations -------------------------------------------------
  const destinations = new WeakMap();

  const originalConnect = net.Socket.prototype.connect;
  net.Socket.prototype.connect = function patchedConnect(...args) {
    let host;
    let port;
    // `net.connect(port, host)` normalises its arguments before delegating to
    // `socket.connect([options])`, so the common path arrives as an array.
    let first = args[0];
    if (Array.isArray(first)) first = first[0];
    if (first && typeof first === "object") {
      port = first.port;
      host = typeof first.host === "string" ? first.host : first.path;
    } else {
      port = first;
      if (typeof args[1] === "string") host = args[1];
    }
    const resolved = {
      host: typeof host === "string" ? host : "localhost",
      port: typeof port === "number" ? port : undefined,
    };
    destinations.set(this, resolved);
    emit({ type: "net.connect", ...resolved });
    return originalConnect.apply(this, args);
  };

  const originalWrite = net.Socket.prototype.write;
  net.Socket.prototype.write = function patchedWrite(chunk, ...rest) {
    const ids = canaryIdsIn(chunk);
    if (ids.length > 0) {
      const target = destinations.get(this) ?? {};
      // `remoteAddress` is only available once the socket is connected, and it
      // is the only way to attribute a write whose connect() we did not see.
      emit({
        type: "net.write",
        host: target.host ?? this.remoteAddress ?? undefined,
        port: target.port ?? this.remotePort ?? undefined,
        canaryIds: ids,
        bytes: typeof chunk === "string" ? Buffer.byteLength(chunk) : chunk?.byteLength,
      });
    }
    return originalWrite.call(this, chunk, ...rest);
  };

  // ---- name resolution ------------------------------------------------------
  const originalLookup = dns.lookup;
  dns.lookup = function patchedLookup(hostname, ...rest) {
    emit({ type: "dns.lookup", host: String(hostname) });
    return originalLookup.call(this, hostname, ...rest);
  };
  if (dns.promises && typeof dns.promises.lookup === "function") {
    const originalPromiseLookup = dns.promises.lookup;
    dns.promises.lookup = function patchedPromiseLookup(hostname, ...rest) {
      emit({ type: "dns.lookup", host: String(hostname) });
      return originalPromiseLookup.call(this, hostname, ...rest);
    };
  }

  // ---- credential file reads ------------------------------------------------
  for (const name of ["readFileSync", "readFile", "openSync", "open", "createReadStream"]) {
    const original = fs[name];
    if (typeof original !== "function") continue;
    fs[name] = function patchedRead(file, ...rest) {
      notePath(file);
      return original.call(this, file, ...rest);
    };
  }
  if (fs.promises) {
    for (const name of ["readFile", "open"]) {
      const original = fs.promises[name];
      if (typeof original !== "function") continue;
      fs.promises[name] = function patchedPromiseRead(file, ...rest) {
        notePath(file);
        return original.call(this, file, ...rest);
      };
    }
  }

  // ---- child processes ------------------------------------------------------
  for (const name of ["spawn", "exec", "execFile", "spawnSync", "execSync", "execFileSync"]) {
    const original = cp[name];
    if (typeof original !== "function") continue;
    cp[name] = function patchedSpawn(command, ...rest) {
      emit({ type: "process.spawn", detail: String(command).slice(0, 160) });
      return original.call(this, command, ...rest);
    };
  }
}

if (LOG) {
  try {
    install();
  } catch {
    /* a broken hook must not take the server down */
  }
}
