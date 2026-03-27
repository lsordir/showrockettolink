var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/converter.ts
var SCHEMES = ["vless://", "vmess://", "trojan://", "ss://"];
function convertLinks(text) {
  const results = [];
  const errors = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    for (const scheme of SCHEMES) {
      const idx = trimmed.indexOf(scheme);
      if (idx === -1) continue;
      let linkPart = trimmed.slice(idx);
      const spaceIdx = linkPart.search(/[\s]/);
      if (spaceIdx !== -1) linkPart = linkPart.slice(0, spaceIdx);
      try {
        results.push(convertLink(linkPart));
      } catch (e) {
        errors.push(`${linkPart.slice(0, 40)}\u2026: ${e instanceof Error ? e.message : e}`);
      }
      break;
    }
  }
  return { results, errors };
}
__name(convertLinks, "convertLinks");
function convertLink(link) {
  if (link.startsWith("vless://")) return convertVless(link);
  if (link.startsWith("vmess://")) return convertVmess(link);
  if (link.startsWith("trojan://")) return convertTrojan(link);
  if (link.startsWith("ss://")) return convertSS(link);
  throw new Error("unsupported protocol");
}
__name(convertLink, "convertLink");
function convertVless(link) {
  const rest = link.slice("vless://".length);
  const [authority, queryStr] = splitAuthorityQuery(rest);
  if (authority.includes("@")) return link;
  const decoded = b64Decode(authority);
  const { security: encryption, uuid, hostPort } = parseUserHostPort(decoded);
  const params = new URLSearchParams(queryStr);
  const q = new URLSearchParams();
  q.set("security", params.get("tls") === "1" ? "tls" : "none");
  setIf(q, "sni", params.get("peer"));
  setIf(q, "alpn", params.get("alpn"));
  q.set("fp", "chrome");
  q.set("type", mapObfs(params.get("obfs")));
  setIf(q, "path", params.get("path"));
  setIf(q, "host", params.get("obfsParam"));
  q.set("encryption", encryption);
  setIf(q, "serviceName", params.get("serviceName"));
  const remarks = params.get("remarks") ?? "";
  let result = `vless://${uuid}@${hostPort}?${q.toString()}`;
  if (remarks) result += "#" + encodeURIComponent(remarks);
  return result;
}
__name(convertVless, "convertVless");
function convertVmess(link) {
  const rest = link.slice("vmess://".length);
  const [b64Part, queryStr] = splitAuthorityQuery(rest);
  const decoded = b64Decode(b64Part).trim();
  if (decoded.startsWith("{")) return link;
  const { security, uuid, hostPort } = parseUserHostPort(decoded);
  const [host, port] = splitHostPort(hostPort);
  const params = new URLSearchParams(queryStr);
  const obfs = params.get("obfs") ?? "";
  const [net, tp] = mapObfsVmess(obfs);
  const cfg = {
    v: "2",
    ps: params.get("remarks") ?? "",
    add: host,
    port,
    id: uuid,
    aid: params.get("alterId") || "0",
    scy: security,
    net,
    type: tp,
    host: params.get("obfsParam") ?? "",
    path: params.get("path") ?? "",
    tls: params.get("tls") === "1" ? "tls" : "",
    sni: params.get("peer") ?? "",
    alpn: params.get("alpn") ?? "",
    fp: "chrome"
  };
  return "vmess://" + btoa(JSON.stringify(cfg));
}
__name(convertVmess, "convertVmess");
function convertTrojan(link) {
  const rest = link.slice("trojan://".length);
  const [authority, queryStr] = splitAuthorityQuery(rest);
  if (authority.includes("@")) return link;
  const decoded = b64Decode(authority);
  const atIdx = decoded.lastIndexOf("@");
  if (atIdx === -1) throw new Error("invalid trojan format");
  const password = decoded.slice(0, atIdx);
  const hostPort = decoded.slice(atIdx + 1);
  const params = new URLSearchParams(queryStr);
  const q = new URLSearchParams();
  const tlsVal = params.get("tls");
  q.set("security", tlsVal === "" || tlsVal === null || tlsVal === "1" ? "tls" : "none");
  setIf(q, "sni", params.get("peer"));
  setIf(q, "alpn", params.get("alpn"));
  q.set("fp", "chrome");
  q.set("type", mapObfs(params.get("obfs")));
  setIf(q, "path", params.get("path"));
  setIf(q, "host", params.get("obfsParam"));
  setIf(q, "serviceName", params.get("serviceName"));
  const remarks = params.get("remarks") ?? "";
  let result = `trojan://${encodeURIComponent(password)}@${hostPort}?${q.toString()}`;
  if (remarks) result += "#" + encodeURIComponent(remarks);
  return result;
}
__name(convertTrojan, "convertTrojan");
function convertSS(link) {
  const rest = link.slice("ss://".length);
  const [mainRaw, queryStr] = splitAuthorityQuery(rest);
  const [mainPart, fragment] = splitOnce(mainRaw, "#");
  if (mainPart.includes("@")) return link;
  let decoded;
  try {
    decoded = b64Decode(mainPart);
  } catch {
    return link;
  }
  const atIdx = decoded.lastIndexOf("@");
  if (atIdx === -1) return link;
  const methodPassword = decoded.slice(0, atIdx);
  const hostPort = decoded.slice(atIdx + 1);
  const params = new URLSearchParams(queryStr);
  const remarks = params.get("remarks") ?? fragment ?? "";
  const encoded = btoa(methodPassword).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  let result = `ss://${encoded}@${hostPort}`;
  if (remarks) result += "#" + encodeURIComponent(remarks);
  return result;
}
__name(convertSS, "convertSS");
function splitAuthorityQuery(s) {
  const hashIdx = s.indexOf("#");
  if (hashIdx !== -1) s = s.slice(0, hashIdx);
  const qIdx = s.indexOf("?");
  if (qIdx === -1) return [s, ""];
  return [s.slice(0, qIdx), s.slice(qIdx + 1)];
}
__name(splitAuthorityQuery, "splitAuthorityQuery");
function splitOnce(s, sep) {
  const idx = s.indexOf(sep);
  if (idx === -1) return [s, void 0];
  return [s.slice(0, idx), s.slice(idx + 1)];
}
__name(splitOnce, "splitOnce");
function b64Decode(s) {
  let padded = s.replace(/-/g, "+").replace(/_/g, "/");
  while (padded.length % 4 !== 0) padded += "=";
  return atob(padded);
}
__name(b64Decode, "b64Decode");
function parseUserHostPort(decoded) {
  const atIdx = decoded.lastIndexOf("@");
  if (atIdx === -1) throw new Error("invalid format: missing @");
  const userPart = decoded.slice(0, atIdx);
  const hostPort = decoded.slice(atIdx + 1);
  const colonIdx = userPart.indexOf(":");
  if (colonIdx !== -1) {
    return { security: userPart.slice(0, colonIdx), uuid: userPart.slice(colonIdx + 1), hostPort };
  }
  return { security: "none", uuid: userPart, hostPort };
}
__name(parseUserHostPort, "parseUserHostPort");
function splitHostPort(hp) {
  const idx = hp.lastIndexOf(":");
  if (idx === -1) return [hp, "443"];
  return [hp.slice(0, idx), hp.slice(idx + 1)];
}
__name(splitHostPort, "splitHostPort");
function mapObfs(obfs) {
  switch (obfs) {
    case "websocket":
      return "ws";
    case "h2":
      return "h2";
    case "grpc":
      return "grpc";
    case "http":
      return "http";
    default:
      return "tcp";
  }
}
__name(mapObfs, "mapObfs");
function mapObfsVmess(obfs) {
  switch (obfs) {
    case "websocket":
      return ["ws", "none"];
    case "http":
      return ["tcp", "http"];
    case "h2":
      return ["h2", "none"];
    case "grpc":
      return ["grpc", "gun"];
    default:
      return ["tcp", "none"];
  }
}
__name(mapObfsVmess, "mapObfsVmess");
function setIf(q, key, val) {
  if (val) q.set(key, val);
}
__name(setIf, "setIf");

// src/index.ts
var AD_URL = "https://www.redgen.net";
var SCHEMES2 = ["vless://", "vmess://", "trojan://", "ss://"];
var index_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/webhook" && request.method === "POST") {
      return handleWebhook(request, env);
    }
    if (url.pathname === "/setup-webhook") {
      return setupWebhook(url, env);
    }
    if (url.pathname === "/") {
      return new Response("V2Ray Link Converter Bot is running.", { status: 200 });
    }
    return new Response("Not found", { status: 404 });
  }
};
async function handleWebhook(request, env) {
  const update = await request.json();
  if (!update.message?.text) {
    return new Response("ok");
  }
  const chatId = update.message.chat.id;
  const messageId = update.message.message_id;
  const text = update.message.text;
  if (text === "/start" || text === "/help") {
    await sendMessage(env, chatId, welcomeText());
    return new Response("ok");
  }
  const hasLink = SCHEMES2.some((s) => text.includes(s));
  if (!hasLink) {
    await sendMessage(
      env,
      chatId,
      "\u26A0\uFE0F No V2Ray link found.\n\nSend me a link starting with:\n\u2022 <code>vless://</code>\n\u2022 <code>vmess://</code>\n\u2022 <code>trojan://</code>\n\u2022 <code>ss://</code>\n\nI will convert Shadowrocket links to the universal format supported by all apps."
    );
    return new Response("ok");
  }
  const { results, errors } = convertLinks(text);
  const reply = buildReply(results, errors);
  await sendMessage(env, chatId, reply, messageId);
  return new Response("ok");
}
__name(handleWebhook, "handleWebhook");
async function setupWebhook(url, env) {
  const webhookUrl = `${url.origin}/webhook`;
  const apiUrl = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/setWebhook?url=${encodeURIComponent(webhookUrl)}`;
  const res = await fetch(apiUrl);
  const body = await res.json();
  return new Response(JSON.stringify(body, null, 2), {
    headers: { "content-type": "application/json" }
  });
}
__name(setupWebhook, "setupWebhook");
async function sendMessage(env, chatId, text, replyTo) {
  const payload = {
    chat_id: chatId,
    text,
    parse_mode: "HTML",
    disable_web_page_preview: true
  };
  if (replyTo) payload.reply_parameters = { message_id: replyTo };
  await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
}
__name(sendMessage, "sendMessage");
function welcomeText() {
  return `\u{1F680} <b>V2Ray Link Converter</b>

Send me any V2Ray link in <b>Shadowrocket</b> format and I'll convert it to the <b>universal standard format</b> compatible with all apps:

\u2705 v2rayN / v2rayNG
\u2705 Nekoray / Nekobox
\u2705 Clash / ClashMeta
\u2705 Sing-box
\u2705 Xray / V2Fly
\u2705 Hiddify

<b>Supported protocols:</b> vless, vmess, trojan, ss

Just paste your link(s) and I'll do the rest!

\u{1F517} <a href="${AD_URL}">Sponsored by RedGen</a>`;
}
__name(welcomeText, "welcomeText");
function buildReply(results, errors) {
  let msg = "";
  if (results.length > 0) {
    msg += "\u2705 <b>Converted \u2014 Universal format:</b>\n\n";
    results.forEach((r, i) => {
      if (results.length > 1) msg += `<b>${i + 1}.</b>
`;
      msg += `<code>${escapeHtml(r)}</code>

`;
    });
  }
  if (errors.length > 0) {
    msg += "\u26A0\uFE0F <b>Errors:</b>\n";
    errors.forEach((e) => {
      msg += `\u2022 ${escapeHtml(e)}
`;
    });
    msg += "\n";
  }
  msg += `\u{1F517} <a href="${AD_URL}">Sponsored by RedGen</a>`;
  return msg;
}
__name(buildReply, "buildReply");
function escapeHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
__name(escapeHtml, "escapeHtml");
export {
  index_default as default
};
//# sourceMappingURL=index.js.map
