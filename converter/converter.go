package converter

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

type VmessConfig struct {
	V    string `json:"v"`
	PS   string `json:"ps"`
	Add  string `json:"add"`
	Port string `json:"port"`
	ID   string `json:"id"`
	Aid  string `json:"aid"`
	Scy  string `json:"scy"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
	SNI  string `json:"sni"`
	ALPN string `json:"alpn"`
	Fp   string `json:"fp,omitempty"`
}

var supportedSchemes = []string{"vless://", "vmess://", "trojan://", "ss://"}

func ConvertLink(link string) (string, error) {
	link = strings.TrimSpace(link)

	switch {
	case strings.HasPrefix(link, "vless://"):
		return convertVless(link)
	case strings.HasPrefix(link, "vmess://"):
		return convertVmess(link)
	case strings.HasPrefix(link, "trojan://"):
		return convertTrojan(link)
	case strings.HasPrefix(link, "ss://"):
		return convertSS(link)
	}

	return "", fmt.Errorf("unsupported protocol")
}

// ConvertLinks processes a text block and converts every V2Ray link found.
func ConvertLinks(text string) ([]string, []error) {
	lines := strings.Split(text, "\n")
	var results []string
	var errors []error

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		for _, scheme := range supportedSchemes {
			idx := strings.Index(line, scheme)
			if idx == -1 {
				continue
			}
			linkPart := line[idx:]
			if sp := strings.IndexAny(linkPart, " \t\r"); sp != -1 {
				linkPart = linkPart[:sp]
			}
			converted, err := ConvertLink(linkPart)
			if err != nil {
				errors = append(errors, fmt.Errorf("%s…: %w", safePrefix(linkPart, 40), err))
			} else {
				results = append(results, converted)
			}
			break
		}
	}

	return results, errors
}

// ---------------------------------------------------------------------------
// VLESS
// ---------------------------------------------------------------------------

func convertVless(link string) (string, error) {
	rest := strings.TrimPrefix(link, "vless://")
	authority, queryStr := splitAuthorityQuery(rest)

	if !isShadowrocketFormat(authority) {
		return link, nil
	}

	decoded, err := tryBase64Decode(authority)
	if err != nil {
		return "", fmt.Errorf("decode vless: %w", err)
	}

	encryption, uuid, hostPort, err := parseDecodedUserHostPort(decoded)
	if err != nil {
		return "", err
	}

	params, _ := url.ParseQuery(queryStr)

	q := url.Values{}
	q.Set("security", mapTLS(params.Get("tls")))
	setIfPresent(q, "sni", params.Get("peer"))
	setIfPresent(q, "alpn", params.Get("alpn"))
	q.Set("fp", "chrome")
	q.Set("type", mapObfs(params.Get("obfs")))
	setIfPresent(q, "path", params.Get("path"))
	setIfPresent(q, "host", params.Get("obfsParam"))
	q.Set("encryption", encryption)

	if svcName := params.Get("serviceName"); svcName != "" {
		q.Set("serviceName", svcName)
	}

	remarks := params.Get("remarks")
	result := fmt.Sprintf("vless://%s@%s?%s", uuid, hostPort, q.Encode())
	if remarks != "" {
		result += "#" + encodeFragment(remarks)
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// VMESS
// ---------------------------------------------------------------------------

func convertVmess(link string) (string, error) {
	rest := strings.TrimPrefix(link, "vmess://")
	b64Part, queryStr := splitAuthorityQuery(rest)

	decoded, err := tryBase64Decode(b64Part)
	if err != nil {
		return "", fmt.Errorf("decode vmess: %w", err)
	}

	decoded = strings.TrimSpace(decoded)
	if strings.HasPrefix(decoded, "{") {
		return link, nil // already v2rayN JSON
	}

	security, uuid, hostPort, err := parseDecodedUserHostPort(decoded)
	if err != nil {
		return "", err
	}

	host, port := splitHostPort(hostPort)
	params, _ := url.ParseQuery(queryStr)

	obfs := params.Get("obfs")
	net, tp := mapObfsVmess(obfs)

	cfg := VmessConfig{
		V:    "2",
		PS:   params.Get("remarks"),
		Add:  host,
		Port: port,
		ID:   uuid,
		Aid:  defaultStr(params.Get("alterId"), "0"),
		Scy:  security,
		Net:  net,
		Type: tp,
		Host: params.Get("obfsParam"),
		Path: params.Get("path"),
		TLS:  mapTLSVmess(params.Get("tls")),
		SNI:  params.Get("peer"),
		ALPN: params.Get("alpn"),
		Fp:   "chrome",
	}

	jsonData, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("marshal vmess: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(jsonData)
	return "vmess://" + encoded, nil
}

// ---------------------------------------------------------------------------
// TROJAN
// ---------------------------------------------------------------------------

func convertTrojan(link string) (string, error) {
	rest := strings.TrimPrefix(link, "trojan://")
	authority, queryStr := splitAuthorityQuery(rest)

	if !isShadowrocketFormat(authority) {
		return link, nil
	}

	decoded, err := tryBase64Decode(authority)
	if err != nil {
		return "", fmt.Errorf("decode trojan: %w", err)
	}

	atIdx := strings.LastIndex(decoded, "@")
	if atIdx == -1 {
		return "", fmt.Errorf("invalid trojan format")
	}
	password := decoded[:atIdx]
	hostPort := decoded[atIdx+1:]

	params, _ := url.ParseQuery(queryStr)

	q := url.Values{}
	tlsVal := params.Get("tls")
	if tlsVal == "" || tlsVal == "1" {
		q.Set("security", "tls")
	} else {
		q.Set("security", "none")
	}
	setIfPresent(q, "sni", params.Get("peer"))
	setIfPresent(q, "alpn", params.Get("alpn"))
	q.Set("fp", "chrome")
	q.Set("type", mapObfs(params.Get("obfs")))
	setIfPresent(q, "path", params.Get("path"))
	setIfPresent(q, "host", params.Get("obfsParam"))

	if svcName := params.Get("serviceName"); svcName != "" {
		q.Set("serviceName", svcName)
	}

	remarks := params.Get("remarks")
	result := fmt.Sprintf("trojan://%s@%s?%s", url.QueryEscape(password), hostPort, q.Encode())
	if remarks != "" {
		result += "#" + encodeFragment(remarks)
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// SHADOWSOCKS
// ---------------------------------------------------------------------------

func convertSS(link string) (string, error) {
	rest := strings.TrimPrefix(link, "ss://")

	mainPart, queryStr := splitAuthorityQuery(rest)

	fragParts := strings.SplitN(mainPart, "#", 2)
	mainPart = fragParts[0]

	if strings.Contains(mainPart, "@") {
		return link, nil // already SIP002 standard
	}

	decoded, err := tryBase64Decode(mainPart)
	if err != nil {
		return link, nil
	}

	atIdx := strings.LastIndex(decoded, "@")
	if atIdx == -1 {
		return link, nil
	}

	methodPassword := decoded[:atIdx]
	hostPort := decoded[atIdx+1:]

	params, _ := url.ParseQuery(queryStr)
	remarks := params.Get("remarks")
	if remarks == "" && len(fragParts) > 1 {
		remarks = fragParts[1]
	}

	encoded := base64.RawURLEncoding.EncodeToString([]byte(methodPassword))

	result := fmt.Sprintf("ss://%s@%s", encoded, hostPort)
	if remarks != "" {
		result += "#" + encodeFragment(remarks)
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func isShadowrocketFormat(authority string) bool {
	return !strings.Contains(authority, "@")
}

func splitAuthorityQuery(s string) (string, string) {
	// Also strip fragment for splitting; we'll handle it via params.remarks
	s = strings.SplitN(s, "#", 2)[0]
	parts := strings.SplitN(s, "?", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return parts[0], ""
}

func tryBase64Decode(s string) (string, error) {
	decoders := []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	}
	for _, dec := range decoders {
		if data, err := dec(s); err == nil && len(data) > 0 {
			return string(data), nil
		}
	}
	return "", fmt.Errorf("base64 decode failed")
}

// parseDecodedUserHostPort parses "security:uuid@host:port" or "uuid@host:port"
func parseDecodedUserHostPort(decoded string) (security, uuid, hostPort string, err error) {
	atIdx := strings.LastIndex(decoded, "@")
	if atIdx == -1 {
		return "", "", "", fmt.Errorf("invalid decoded format: missing @")
	}
	userPart := decoded[:atIdx]
	hostPort = decoded[atIdx+1:]

	if colonIdx := strings.Index(userPart, ":"); colonIdx != -1 {
		security = userPart[:colonIdx]
		uuid = userPart[colonIdx+1:]
	} else {
		security = "none"
		uuid = userPart
	}
	return
}

func splitHostPort(hp string) (string, string) {
	idx := strings.LastIndex(hp, ":")
	if idx == -1 {
		return hp, "443"
	}
	return hp[:idx], hp[idx+1:]
}

func mapTLS(val string) string {
	if val == "1" {
		return "tls"
	}
	return "none"
}

func mapTLSVmess(val string) string {
	if val == "1" {
		return "tls"
	}
	return ""
}

func mapObfs(obfs string) string {
	switch obfs {
	case "websocket":
		return "ws"
	case "h2":
		return "h2"
	case "grpc":
		return "grpc"
	case "http":
		return "http"
	default:
		return "tcp"
	}
}

func mapObfsVmess(obfs string) (net, tp string) {
	switch obfs {
	case "websocket":
		return "ws", "none"
	case "http":
		return "tcp", "http"
	case "h2":
		return "h2", "none"
	case "grpc":
		return "grpc", "gun"
	default:
		return "tcp", "none"
	}
}

func setIfPresent(q url.Values, key, val string) {
	if val != "" {
		q.Set(key, val)
	}
}

func defaultStr(val, fallback string) string {
	if val == "" {
		return fallback
	}
	return val
}

func encodeFragment(s string) string {
	return url.PathEscape(s)
}

func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
