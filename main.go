package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"showrockettolink/converter"
)

const adURL = "https://www.redgen.net"

func main() {
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	if token == "" {
		log.Fatal("TELEGRAM_BOT_TOKEN environment variable is not set")
	}

	bot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		log.Fatalf("Failed to create bot: %v", err)
	}

	log.Printf("Bot started: @%s", bot.Self.UserName)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message == nil {
			continue
		}

		text := update.Message.Text
		if text == "" {
			continue
		}

		chatID := update.Message.Chat.ID

		if text == "/start" || text == "/help" {
			sendWelcome(bot, chatID)
			continue
		}

		if !containsV2RayLink(text) {
			msg := tgbotapi.NewMessage(chatID,
				"⚠️ No V2Ray link found.\n\n"+
					"Send me a link starting with:\n"+
					"• <code>vless://</code>\n"+
					"• <code>vmess://</code>\n"+
					"• <code>trojan://</code>\n"+
					"• <code>ss://</code>\n\n"+
					"I will convert Shadowrocket links to the universal format supported by all apps.")
			msg.ParseMode = "HTML"
			bot.Send(msg)
			continue
		}

		results, errs := converter.ConvertLinks(text)
		reply := buildReply(results, errs)

		msg := tgbotapi.NewMessage(chatID, reply)
		msg.ParseMode = "HTML"
		msg.ReplyToMessageID = update.Message.MessageID
		msg.DisableWebPagePreview = true
		bot.Send(msg)
	}
}

func sendWelcome(bot *tgbotapi.BotAPI, chatID int64) {
	welcome := "🚀 <b>V2Ray Link Converter</b>\n\n" +
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
		fmt.Sprintf("🔗 <a href=\"%s\">Sponsored by RedGen</a>", adURL)

	msg := tgbotapi.NewMessage(chatID, welcome)
	msg.ParseMode = "HTML"
	msg.DisableWebPagePreview = true
	bot.Send(msg)
}

func containsV2RayLink(text string) bool {
	for _, scheme := range []string{"vless://", "vmess://", "trojan://", "ss://"} {
		if strings.Contains(text, scheme) {
			return true
		}
	}
	return false
}

func buildReply(results []string, errs []error) string {
	var b strings.Builder

	if len(results) > 0 {
		b.WriteString("✅ <b>Converted — Universal format:</b>\n\n")
		for i, r := range results {
			if len(results) > 1 {
				b.WriteString(fmt.Sprintf("<b>%d.</b>\n", i+1))
			}
			b.WriteString(fmt.Sprintf("<code>%s</code>\n\n", escapeHTML(r)))
		}
	}

	if len(errs) > 0 {
		b.WriteString("⚠️ <b>Errors:</b>\n")
		for _, e := range errs {
			b.WriteString(fmt.Sprintf("• %s\n", escapeHTML(e.Error())))
		}
		b.WriteString("\n")
	}

	b.WriteString(fmt.Sprintf("🔗 <a href=\"%s\">Sponsored by RedGen</a>", adURL))

	return b.String()
}

func escapeHTML(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}
