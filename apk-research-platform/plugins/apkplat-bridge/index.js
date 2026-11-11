/**
 * apkplat-bridge — the DSH-side half of the P1 bridge (taskbook §2.2).
 *
 * What it does, and what it deliberately does not do:
 *
 *  - it asks the platform for a run assignment at activation, then registers exactly
 *    the tools that assignment handed it (the platform is the boundary; this filter
 *    only keeps the model's context small);
 *  - every execute() forwards the model-chosen arguments to the platform and returns
 *    whatever the platform answered, refusals included — no local guessing, no local
 *    fallbacks that could make a refused call look successful;
 *  - the run token is read once from an owner-only file and kept in this module's
 *    closure. It is never logged, never echoed into a tool result and never appears in
 *    a prompt.
 *
 * Loading note: the plugin lives outside the DSH install, so a bare import of
 * `@deepseek-ai/dsh-tools` may not resolve from here. We therefore try the normal
 * import first and fall back to createRequire() against the installed app, which works
 * for both the packaged desktop app and a headless ELECTRON_RUN_AS_NODE run.
 */

import { createRequire } from "node:module";
import { appendFile, readFile } from "node:fs/promises";

export const name = "apkplat-bridge";
export const inject = ["tools"];

const PLUGIN_VERSION = "1.0.0";
const DEFAULT_TIMEOUT_MS = 60000;
const DEFAULT_MAX_INLINE_BYTES = 24000;

async function loadDefineTool() {
  try {
    const mod = await import("@deepseek-ai/dsh-tools");
    if (typeof mod.defineTool === "function") return mod.defineTool;
  } catch {
    /* fall through to the createRequire path */
  }
  const candidates = [
    process.env.APKPLAT_DSH_ASAR,
    process.env.DSH_INSTALL ? `${process.env.DSH_INSTALL}/resources/app.asar` : undefined,
    "C:/Users/YHY/AppData/Local/Programs/DSH NEXT/resources/app.asar",
  ].filter(Boolean);
  for (const base of candidates) {
    try {
      const req = createRequire(`${base}/package.json`);
      const mod = req("@deepseek-ai/dsh-tools");
      if (mod && typeof mod.defineTool === "function") return mod.defineTool;
    } catch {
      /* try the next candidate */
    }
  }
  throw new Error(
    "apkplat-bridge: cannot load @deepseek-ai/dsh-tools. " +
      "Set APKPLAT_DSH_ASAR to <DSH install>/resources/app.asar so the bridge can resolve the host API.",
  );
}

/** Convert the platform's JSON-Schema fragment into the host parameter DSL. */
function toParameterDsl(schema) {
  const properties = (schema && schema.properties) || {};
  const out = {};
  for (const [key, spec] of Object.entries(properties)) {
    const entry = { type: spec.type === "number" ? "number" : spec.type === "boolean" ? "boolean" : "string" };
    if (spec.description) entry.description = spec.description;
    if (Array.isArray(spec.enum) && spec.enum.length > 0) entry.enum = spec.enum;
    if (spec.required === true) entry.required = true;
    out[key] = entry;
  }
  return out;
}

function truncate(text, maxBytes) {
  if (Buffer.byteLength(text, "utf8") <= maxBytes) return { text, truncated: false };
  const buf = Buffer.from(text, "utf8").subarray(0, maxBytes);
  return {
    text: `${buf.toString("utf8")}\n\n[apkplat-bridge] result truncated at ${maxBytes} bytes; query with a narrower target or read the artifact id it mentions`,
    truncated: true,
  };
}

async function readToken(tokenFile) {
  const raw = await readFile(tokenFile, "utf8");
  const token = raw.trim();
  if (!token) throw new Error(`apkplat-bridge: token file ${tokenFile} is empty`);
  return token;
}

async function postJson(url, token, body, timeoutMs) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body ?? {}),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await response.text();
  let parsed;
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    parsed = { ok: false, error_code: "bad_response", message: text.slice(0, 400) };
  }
  return { status: response.status, body: parsed };
}

export async function apply(ctx, config) {
  const settings = {
    platform_url: (config?.platform_url || "http://127.0.0.1:8765").replace(/\/+$/, ""),
    token_file: config?.token_file,
    trace_file: config?.trace_file,
    timeout_ms: Number(config?.timeout_ms || DEFAULT_TIMEOUT_MS),
    max_inline_bytes: Number(config?.max_inline_bytes || DEFAULT_MAX_INLINE_BYTES),
    fail_on_error: config?.fail_on_error !== false,
  };
  if (!settings.token_file) throw new Error("apkplat-bridge: config.token_file is required");

  let token;
  try {
    token = await readToken(settings.token_file);
  } catch (error) {
    if (settings.fail_on_error) throw error;
    ctx.logger?.warn?.(`apkplat-bridge: token unavailable (${error.message})`);
    return;
  }

  let handshake;
  try {
    handshake = await postJson(
      `${settings.platform_url}/api/bridge/handshake`,
      token,
      { plugin_version: PLUGIN_VERSION, model_id: config?.model_id },
      settings.timeout_ms,
    );
  } catch (error) {
    if (settings.fail_on_error) throw new Error(`apkplat-bridge: handshake failed: ${error.message}`);
    return;
  }
  if (!handshake.body || handshake.body.ok !== true) {
    const detail = JSON.stringify(handshake.body || {}).slice(0, 300);
    if (settings.fail_on_error) throw new Error(`apkplat-bridge: handshake refused (${handshake.status}): ${detail}`);
    return;
  }

  const run = handshake.body.run || {};
  const tools = Array.isArray(handshake.body.tools) ? handshake.body.tools : [];
  const defineTool = await loadDefineTool();

  const trace = async (record) => {
    if (!settings.trace_file) return;
    try {
      await appendFile(settings.trace_file, `${JSON.stringify(record)}\n`, "utf8");
    } catch {
      /* tracing must never break a tool call */
    }
  };

  await trace({
    ts: new Date().toISOString(),
    event: "run_assigned",
    run_id: run.run_id,
    project_id: run.project_id,
    task_id: run.task_id,
    role_id: run.role_id,
    plugin_version: PLUGIN_VERSION,
    tools: tools.map((tool) => tool.name),
  });

  for (const entry of tools) {
    ctx.tools.register(
      defineTool({
        name: entry.name,
        description: entry.description,
        parameters: toParameterDsl(entry.parameters),
        output: {
          schema: {
            type: "object",
            additionalProperties: false,
            properties: {
              ok: { type: "boolean", required: true },
              text: { type: "string", required: true },
            },
          },
          render: (_args, value) => [{ type: "text", text: value.text }],
        },
        isConcurrencySafe: () => true,
        async execute(args) {
          const started = Date.now();
          // The platform echoes this id back, so a plugin-side record and the server-side
          // trace row can be paired one-to-one even when a call never lands.
          const requestId = `req_${started.toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
          let payload;
          try {
            const response = await postJson(
              `${settings.platform_url}/api/bridge/tools/${encodeURIComponent(entry.name)}`,
              token,
              { arguments: args ?? {}, request_id: requestId },
              settings.timeout_ms,
            );
            payload = { ok: response.body?.ok === true, text: JSON.stringify(response.body ?? {}, null, 2) };
            await trace({
              ts: new Date().toISOString(),
              event: "tool_call",
              run_id: run.run_id,
              tool: entry.name,
              args,
              request_id: response.body?.request_id ?? requestId,
              http_status: response.status,
              ok: payload.ok,
              error_code: response.body?.error_code ?? null,
              duration_ms: Date.now() - started,
            });
          } catch (error) {
            payload = {
              ok: false,
              text: JSON.stringify({ ok: false, error_code: "bridge_unreachable", message: String(error && error.message) }),
            };
            await trace({
              ts: new Date().toISOString(),
              event: "tool_call",
              run_id: run.run_id,
              tool: entry.name,
              args,
              request_id: requestId,
              ok: false,
              error_code: "bridge_unreachable",
              duration_ms: Date.now() - started,
            });
          }
          const bounded = truncate(payload.text, settings.max_inline_bytes);
          return { ok: payload.ok, text: bounded.text };
        },
      }),
    );
  }

  ctx.logger?.info?.(
    `apkplat-bridge: run ${run.run_id} role=${run.role_id} tools=${tools.map((tool) => tool.name).join(",")}`,
  );
}

export const Config = undefined;
