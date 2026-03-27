import { convertLinks } from "./converter";

const AD_URL = "https://www.redgen.net";
const SCHEMES = ["vless://", "vmess://", "trojan://", "ss://"];

interface Env {
  TELEGRAM_BOT_TOKEN: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
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
  },
};

// ---------------------------------------------------------------------------
// Webhook handler – receives Telegram updates
// ---------------------------------------------------------------------------

async function handleWebhook(request: Request, env: Env): Promise<Response> {
  const update = (await request.json()) as TelegramUpdate;

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

  const hasLink = SCHEMES.some((s) => text.includes(s));
  if (!hasLink) {
    await sendMessage(
      env,
      chatId,
      "⚠️ No V2Ray link found.\n\n" +
        "Send me a link starting with:\n" +
        "• <code>vless://</code>\n" +
        "• <code>vmess://</code>\n" +
        "• <code>trojan://</code>\n" +
        "• <code>ss://</code>\n\n" +
        "I will convert Shadowrocket links to the universal format supported by all apps.",
    );
    return new Response("ok");
  }

  const { results, errors } = convertLinks(text);
  const reply = buildReply(results, errors);

  await sendMessage(env, chatId, reply, messageId);
  return new Response("ok");
}

// ---------------------------------------------------------------------------
// Register webhook with Telegram
// ---------------------------------------------------------------------------

async function setupWebhook(url: URL, env: Env): Promise<Response> {
  const webhookUrl = `${url.origin}/webhook`;
  const apiUrl = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/setWebhook?url=${encodeURIComponent(webhookUrl)}`;

  const res = await fetch(apiUrl);
  const body = await res.json();

  return new Response(JSON.stringify(body, null, 2), {
    headers: { "content-type": "application/json" },
  });
}

// ---------------------------------------------------------------------------
// Telegram API helpers
// ---------------------------------------------------------------------------

async function sendMessage(
  env: Env,
  chatId: number,
  text: string,
  replyTo?: number,
): Promise<void> {
  const payload: Record<string, unknown> = {
    chat_id: chatId,
    text,
    parse_mode: "HTML",
    disable_web_page_preview: true,
  };
  if (replyTo) payload.reply_parameters = { message_id: replyTo };

  await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

// ---------------------------------------------------------------------------
// Message builders
// ---------------------------------------------------------------------------

function welcomeText(): string {
  return (
    "🚀 <b>V2Ray Link Converter</b>\n\n" +
    "Send me any V2Ray link in <b>Shadowrocket</b> format and I'll convert it " +
    "to the <b>universal standard format</b> compatible with all apps:\n\n" +
    "✅ v2rayN / v2rayNG\n" +
    "✅ Nekoray / Nekobox\n" +
    "✅ Clash / ClashMeta\n" +
    "✅ Sing-box\n" +
    "✅ Xray / V2Fly\n" +
    "✅ Hiddify\n\n" +
    "<b>Supported protocols:</b> vless, vmess, trojan, ss\n\n" +
    "Just paste your link(s) and I'll do the rest!\n\n" +
    `🔗 <a href="${AD_URL}">Sponsored by RedGen</a>`
  );
}

function buildReply(results: string[], errors: string[]): string {
  let msg = "";

  if (results.length > 0) {
    msg += "✅ <b>Converted — Universal format:</b>\n\n";
    results.forEach((r, i) => {
      if (results.length > 1) msg += `<b>${i + 1}.</b>\n`;
      msg += `<code>${escapeHtml(r)}</code>\n\n`;
    });
  }

  if (errors.length > 0) {
    msg += "⚠️ <b>Errors:</b>\n";
    errors.forEach((e) => {
      msg += `• ${escapeHtml(e)}\n`;
    });
    msg += "\n";
  }

  msg += `🔗 <a href="${AD_URL}">Sponsored by RedGen</a>`;
  return msg;
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ---------------------------------------------------------------------------
// Telegram types (minimal)
// ---------------------------------------------------------------------------

interface TelegramUpdate {
  message?: {
    message_id: number;
    chat: { id: number };
    text?: string;
  };
}
