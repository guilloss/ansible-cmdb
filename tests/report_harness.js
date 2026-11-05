// Exécute le JavaScript réel du rapport sur un DOM minimal et affiche le HTML de chaque route.
// Usage : node report_harness.js rapport.html route1 route2...
const fs = require("fs"), vm = require("vm");
const html = fs.readFileSync(process.argv[2], "utf8");
const data = html.match(/id="cmdb-data">([^<]*)</)[1];
const code = html.match(/<script>\n"use strict";([\s\S]*)<\/script>/)[1];
const els = {};
const el = id => els[id] || (els[id] = {id, innerHTML: "", textContent: "", dataset: {}, style: {}, value: "", hidden: false,
  querySelector: () => null, querySelectorAll: () => [], focus() {}, setSelectionRange() {}, addEventListener() {}});
const timers = [];
const sandbox = {
  document: {querySelector: s => s[0] === "#" ? el(s.slice(1)) : null, title: "", documentElement: {dataset: {}},
    getElementById: id => id === "cmdb-data" ? {textContent: data} : el(id), createElement: () => ({})},
  location: {hash: ""}, history: {replaceState() {}}, localStorage: {getItem: () => null, setItem() {}},
  matchMedia: () => ({matches: false}), setTimeout: f => { timers.push(f); return timers.length; }, clearTimeout() {},
  atob, Uint8Array, Blob, Response, DecompressionStream, URLSearchParams, URL, console, Intl, TextDecoder,
};
sandbox.window = {addEventListener() {}, scrollTo() {}};
const ctx = vm.createContext(sandbox);
vm.runInContext('"use strict";' + code + ";globalThis.__route = route;", ctx);
(async () => {
  for (let i = 0; i < 50 && !els.view?.innerHTML; i++) await new Promise(r => globalThis.setTimeout(r, 20));
  const out = {};
  for (const r of process.argv.slice(3)) {
    sandbox.location.hash = "#/" + r;
    sandbox.__route();
    let body = els.view.innerHTML;
    while (timers.length) timers.shift()();
    for (const [id, e] of Object.entries(els)) if (/^t[a-z0-9]{6}$|^t[a-z0-9]{5}$/.test(id) && e.innerHTML) { body += "\n" + e.innerHTML; e.innerHTML = ""; }
    out[r] = body;
  }
  console.log(JSON.stringify(out));
})().catch(e => { console.error(e); process.exit(1); });
