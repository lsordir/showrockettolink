/**
 * Quick helper to register the Telegram webhook from CLI.
 *
 * Usage:
 *   TELEGRAM_BOT_TOKEN=xxx WORKER_URL=https://showrockettolink.<your-subdomain>.workers.dev \
 *     node scripts/set-webhook.mjs
 */

const token = process.env.TELEGRAM_BOT_TOKEN;
const workerUrl = process.env.WORKER_URL;

if (!token || !workerUrl) {
  console.error("Set TELEGRAM_BOT_TOKEN and WORKER_URL env vars first.");
  process.exit(1);
}

const webhookUrl = `${workerUrl.replace(/\/$/, "")}/webhook`;
const apiUrl = `https://api.telegram.org/bot${token}/setWebhook?url=${encodeURIComponent(webhookUrl)}`;

const res = await fetch(apiUrl);
const body = await res.json();
console.log(JSON.stringify(body, null, 2));
