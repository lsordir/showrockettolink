interface VmessConfig {
  v: string;
  ps: string;
  add: string;
  port: string;
  id: string;
  aid: string;
  scy: string;
  net: string;
  type: string;
  host: string;
  path: string;
  tls: string;
  sni: string;
  alpn: string;
  fp: string;
}

const SCHEMES = ["vless://", "vmess://", "trojan://", "ss://"] as const;

export function convertLinks(text: string): { results: string[]; errors: string[] } {
  const results: string[] = [];
  const errors: string[] = [];

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
        errors.push(`${linkPart.slice(0, 40)}…: ${e instanceof Error ? e.message : e}`);
      }
      break;
    }
  }

  return { results, errors };
}

export function convertLink(link: string): string {
  if (link.startsWith("vless://")) return convertVless(link);
  if (link.startsWith("vmess://")) return convertVmess(link);
  if (link.startsWith("trojan://")) return convertTrojan(link);
  if (link.startsWith("ss://")) return convertSS(link);
  throw new Error("unsupported protocol");
}

// ---------------------------------------------------------------------------
// VLESS
// ---------------------------------------------------------------------------

function convertVless(link: string): string {
  const rest = link.slice("vless://".length);
  const [authority, queryStr] = splitAuthorityQuery(rest);

  if (authority.includes("@")) return link; // already standard

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

// ---------------------------------------------------------------------------
// VMESS
// ---------------------------------------------------------------------------

function convertVmess(link: string): string {
  const rest = link.slice("vmess://".length);
  const [b64Part, queryStr] = splitAuthorityQuery(rest);

  const decoded = b64Decode(b64Part).trim();
  if (decoded.startsWith("{")) return link; // already v2rayN JSON

  const { security, uuid, hostPort } = parseUserHostPort(decoded);
  const [host, port] = splitHostPort(hostPort);
  const params = new URLSearchParams(queryStr);

  const obfs = params.get("obfs") ?? "";
  const [net, tp] = mapObfsVmess(obfs);

  const cfg: VmessConfig = {
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
    fp: "chrome",
  };

  return "vmess://" + btoa(JSON.stringify(cfg));
}

// ---------------------------------------------------------------------------
// TROJAN
// ---------------------------------------------------------------------------

function convertTrojan(link: string): string {
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

// ---------------------------------------------------------------------------
// SHADOWSOCKS
// ---------------------------------------------------------------------------

function convertSS(link: string): string {
  const rest = link.slice("ss://".length);
  const [mainRaw, queryStr] = splitAuthorityQuery(rest);

  const [mainPart, fragment] = splitOnce(mainRaw, "#");
  if (mainPart.includes("@")) return link; // already SIP002

  let decoded: string;
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

  const encoded = btoa(methodPassword)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  let result = `ss://${encoded}@${hostPort}`;
  if (remarks) result += "#" + encodeURIComponent(remarks);
  return result;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function splitAuthorityQuery(s: string): [string, string] {
  const hashIdx = s.indexOf("#");
  if (hashIdx !== -1) s = s.slice(0, hashIdx);
  const qIdx = s.indexOf("?");
  if (qIdx === -1) return [s, ""];
  return [s.slice(0, qIdx), s.slice(qIdx + 1)];
}

function splitOnce(s: string, sep: string): [string, string | undefined] {
  const idx = s.indexOf(sep);
  if (idx === -1) return [s, undefined];
  return [s.slice(0, idx), s.slice(idx + 1)];
}

function b64Decode(s: string): string {
  let padded = s.replace(/-/g, "+").replace(/_/g, "/");
  while (padded.length % 4 !== 0) padded += "=";
  return atob(padded);
}

function parseUserHostPort(decoded: string): { security: string; uuid: string; hostPort: string } {
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

function splitHostPort(hp: string): [string, string] {
  const idx = hp.lastIndexOf(":");
  if (idx === -1) return [hp, "443"];
  return [hp.slice(0, idx), hp.slice(idx + 1)];
}

function mapObfs(obfs: string | null): string {
  switch (obfs) {
    case "websocket": return "ws";
    case "h2":        return "h2";
    case "grpc":      return "grpc";
    case "http":      return "http";
    default:          return "tcp";
  }
}

function mapObfsVmess(obfs: string): [net: string, type: string] {
  switch (obfs) {
    case "websocket": return ["ws", "none"];
    case "http":      return ["tcp", "http"];
    case "h2":        return ["h2", "none"];
    case "grpc":      return ["grpc", "gun"];
    default:          return ["tcp", "none"];
  }
}

function setIf(q: URLSearchParams, key: string, val: string | null | undefined): void {
  if (val) q.set(key, val);
}
