// The test endpoint's answers (worker.js; D532, K3). Run with: node --test endpoint/
import assert from "node:assert/strict";
import { test } from "node:test";
import worker from "./worker.js";

const ask = (path, init = {}) => worker.fetch(new Request(`https://stop-test.example${path}`, init));
const KEY = "0123456789abcdef0123456789abcdef";

test("the open path answers anyone, with a fixed reply that is never cached", async () => {
  const r = await ask("/open");
  assert.equal(r.status, 200);
  assert.equal(await r.text(), "ok");
  assert.equal(r.headers.get("cache-control"), "no-store");
});

test("the key path answers only a run's key, as an outside service answers only its key", async () => {
  assert.equal((await ask("/key", { headers: { authorization: `Bearer ${KEY}` } })).status, 200);
  for (const bad of ["", `Bearer ${KEY.toUpperCase()}`, `Bearer ${KEY}0`, "Bearer not-a-key", KEY]) {
    assert.equal((await ask("/key", { headers: bad ? { authorization: bad } : {} })).status, 401, bad);
  }
});

test("nothing else is answered, and nothing but GET", async () => {
  assert.equal((await ask("/")).status, 404);
  assert.equal((await ask("/open", { method: "POST", body: "x" })).status, 405);
});

test("it writes no log and keeps nothing: no console call, no storage binding", async () => {
  const fs = await import("node:fs");
  const source = fs.readFileSync(new URL("./worker.js", import.meta.url), "utf8");
  assert.ok(!/console\./.test(source.replace(/^\s*\/\/.*$/gm, "")));
  const config = fs.readFileSync(new URL("./wrangler.toml", import.meta.url), "utf8");
  assert.match(config, /\[observability\]\s*\nenabled = false\s*\nlogpush = false/);
  assert.ok(!/kv_namespaces|d1_databases|r2_buckets|durable_objects|analytics_engine/.test(config));
});
