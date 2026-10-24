// Arvaken's test endpoint for the stop test (D532, K3): "the open-internet and outside-key paths call a test
// endpoint Arvaken runs, never a real third-party service".
//
// GET /open answers anyone. GET /key answers only a request that carries a run's key, as an outside service answers
// only a caller holding its key: a bearer key of 32 hexadecimal characters, which the kit makes for each run.
// Every answer is a fixed reply. This code keeps nothing: it writes no log, stores nothing, and reads nothing of a
// request but its path and that one header. Its configuration (wrangler.toml) turns Cloudflare's request logs off.
// Cloudflare still keeps its standard records of each request, as the README's one description says.

const OK = () => new Response("ok", { status: 200, headers: { "content-type": "text/plain", "cache-control": "no-store" } });
const NO = (status) => new Response(null, { status, headers: { "cache-control": "no-store" } });
const KEY = /^Bearer [0-9a-f]{32}$/;

export default {
  async fetch(request) {
    if (request.method !== "GET") return NO(405);
    const path = new URL(request.url).pathname;
    if (path === "/open") return OK();
    if (path === "/key") return KEY.test(request.headers.get("authorization") || "") ? OK() : NO(401);
    return NO(404);
  },
};
