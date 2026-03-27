package converter

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestConvertVlessShadowrocket(t *testing.T) {
	input := "vless://bm9uZToyZWZiZTc0NC1mNzRiLTQ0MGEtODMxNy0xYTg4NWVlYjZjMTVAaXIyMjQuZGV2d2F3ZS5pcjoxNjMyMw?path=/api&remarks=ORGINAL-test&obfs=websocket&tls=1&peer=ir224.devwawe.ir&alpn=http/1.1,h2,h3"

	result, err := ConvertLink(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	u, err := url.Parse(result)
	if err != nil {
		t.Fatalf("result is not a valid URL: %v", err)
	}

	if u.Scheme != "vless" {
		t.Errorf("scheme = %q, want vless", u.Scheme)
	}
	if u.User.Username() != "2efbe744-f74b-440a-8317-1a885eeb6c15" {
		t.Errorf("uuid = %q", u.User.Username())
	}
	if u.Host != "ir224.devwawe.ir:16323" {
		t.Errorf("host = %q", u.Host)
	}

	q := u.Query()
	if q.Get("security") != "tls" {
		t.Errorf("security = %q, want tls", q.Get("security"))
	}
	if q.Get("sni") != "ir224.devwawe.ir" {
		t.Errorf("sni = %q", q.Get("sni"))
	}
	if q.Get("type") != "ws" {
		t.Errorf("type = %q, want ws", q.Get("type"))
	}
	if q.Get("path") != "/api" {
		t.Errorf("path = %q", q.Get("path"))
	}
	if q.Get("encryption") != "none" {
		t.Errorf("encryption = %q, want none", q.Get("encryption"))
	}
	if !strings.Contains(q.Get("alpn"), "h2") {
		t.Errorf("alpn = %q, expected h2", q.Get("alpn"))
	}

	if u.Fragment != "ORGINAL-test" && !strings.Contains(result, "ORGINAL-test") {
		t.Errorf("fragment missing ORGINAL-test, got %q", u.Fragment)
	}

	t.Logf("Converted VLESS:\n%s", result)
}

func TestConvertVmessShadowrocket(t *testing.T) {
	input := "vmess://YXV0bzpiYzZhMzQ5Mi1kMTYxLTQ3NmEtOWE0Yi1lNGM2NDhiZGE1NjlAZTEtb3JpZ2luLTI1NzgzNDY1NzQucmlmdGVyLnpvbmU6ODA?path=/67uQlXAHLtW2Oshhk25FV&remarks=MTN%20%7C%20zone:%20Dynamic%20%F0%9F%87%BA%F0%9F%87%B8%F0%9F%87%AF%F0%9F%87%B5%F0%9F%87%B9%F0%9F%87%B7%F0%9F%87%A9%F0%9F%87%AA%20-%20VMESS-2&obfsParam=e1-origin-2578346574.rifter.zone&obfs=http&alpn=http/1.1&alterId=0"

	result, err := ConvertLink(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(result, "vmess://") {
		t.Fatalf("expected vmess:// prefix, got %s", result)
	}

	b64 := strings.TrimPrefix(result, "vmess://")
	jsonData, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("failed to decode result base64: %v", err)
	}

	var cfg VmessConfig
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		t.Fatalf("failed to unmarshal vmess JSON: %v", err)
	}

	if cfg.V != "2" {
		t.Errorf("v = %q, want 2", cfg.V)
	}
	if cfg.ID != "bc6a3492-d161-476a-9a4b-e4c648bda569" {
		t.Errorf("id = %q", cfg.ID)
	}
	if cfg.Add != "e1-origin-2578346574.rifter.zone" {
		t.Errorf("add = %q", cfg.Add)
	}
	if cfg.Port != "80" {
		t.Errorf("port = %q", cfg.Port)
	}
	if cfg.Scy != "auto" {
		t.Errorf("scy = %q, want auto", cfg.Scy)
	}
	if cfg.Net != "tcp" {
		t.Errorf("net = %q, want tcp", cfg.Net)
	}
	if cfg.Type != "http" {
		t.Errorf("type = %q, want http", cfg.Type)
	}
	if cfg.Host != "e1-origin-2578346574.rifter.zone" {
		t.Errorf("host = %q", cfg.Host)
	}
	if cfg.Path != "/67uQlXAHLtW2Oshhk25FV" {
		t.Errorf("path = %q", cfg.Path)
	}
	if cfg.Aid != "0" {
		t.Errorf("aid = %q, want 0", cfg.Aid)
	}
	if !strings.Contains(cfg.PS, "VMESS-2") {
		t.Errorf("ps = %q, expected to contain VMESS-2", cfg.PS)
	}

	t.Logf("Converted VMESS JSON:\n%s", string(jsonData))
}

func TestStandardVlessPassthrough(t *testing.T) {
	input := "vless://2efbe744-f74b-440a-8317-1a885eeb6c15@ir224.devwawe.ir:16323?security=tls&sni=ir224.devwawe.ir&alpn=http/1.1,h2,h3&fp=chrome&type=ws&path=/api&encryption=none#ORGINAL-test"
	result, err := ConvertLink(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != input {
		t.Errorf("standard link was modified:\n  input:  %s\n  output: %s", input, result)
	}
}

func TestConvertMultipleLinks(t *testing.T) {
	input := `vless://bm9uZToyZWZiZTc0NC1mNzRiLTQ0MGEtODMxNy0xYTg4NWVlYjZjMTVAaXIyMjQuZGV2d2F3ZS5pcjoxNjMyMw?path=/api&remarks=ORGINAL-test&obfs=websocket&tls=1&peer=ir224.devwawe.ir&alpn=http/1.1,h2,h3
vmess://YXV0bzpiYzZhMzQ5Mi1kMTYxLTQ3NmEtOWE0Yi1lNGM2NDhiZGE1NjlAZTEtb3JpZ2luLTI1NzgzNDY1NzQucmlmdGVyLnpvbmU6ODA?path=/67uQlXAHLtW2Oshhk25FV&remarks=test&obfsParam=e1-origin-2578346574.rifter.zone&obfs=http&alpn=http/1.1&alterId=0`

	results, errs := ConvertLinks(input)
	if len(errs) > 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if !strings.HasPrefix(results[0], "vless://") {
		t.Errorf("first result should be vless, got %s", results[0][:20])
	}
	if !strings.HasPrefix(results[1], "vmess://") {
		t.Errorf("second result should be vmess, got %s", results[1][:20])
	}
}
