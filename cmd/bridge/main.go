package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	htmlpkg "html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
const lang = "en-US"

type Server struct {
	mu         sync.Mutex
	token      string
	tokenAt    time.Time
	items      map[string]Item
	selected   string
	lastErr    string
	cooldown   time.Time
	active     map[uint64]context.CancelFunc
	nextStream uint64
}
type Item struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
	Size int64  `json:"size"`
	Link string `json:"-"`
}

var s = &Server{items: map[string]Item{}, active: map[uint64]context.CancelFunc{}}

func trustRoots() *x509.CertPool {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	for _, loc := range []string{"/data/adb/modules/gofile_vlc_bridge/cacert.pem", "/system/etc/security/cacerts.pem"} {
		if b, e := os.ReadFile(loc); e == nil {
			roots.AppendCertsFromPEM(b)
		}
	}
	return roots
}

var client = &http.Client{Timeout: 40 * time.Second, Transport: &http.Transport{DialContext: androidDial, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: trustRoots(), MinVersion: tls.VersionTLS12}}, CheckRedirect: func(r *http.Request, via []*http.Request) error {
	if len(via) > 5 {
		return http.ErrUseLastResponse
	}
	return nil
}}

// Static Go binaries do not use Android netd. Discover DNS servers from Android
// system properties instead of blindly trusting /etc/resolv.conf (::1).
func androidDNS() []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if net.ParseIP(v) != nil && !net.ParseIP(v).IsLoopback() && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	if v := os.Getenv("GOFILE_DNS"); v != "" {
		for _, x := range strings.Split(v, ",") {
			add(x)
		}
	}
	for _, key := range []string{"net.dns1", "net.dns2", "net.dns3", "net.dns4", "dhcp.wlan0.dns1", "dhcp.wlan0.dns2", "dhcp.rmnet_data0.dns1", "dhcp.rmnet_data0.dns2"} {
		b, e := exec.Command("getprop", key).Output()
		if e == nil {
			add(string(b))
		}
	}
	// Some Android versions expose only per-interface DNS properties.
	if b, e := exec.Command("getprop").Output(); e == nil {
		sc := bufio.NewScanner(strings.NewReader(string(b)))
		for sc.Scan() {
			line := sc.Text()
			if !strings.Contains(line, ".dns") {
				continue
			}
			parts := strings.Split(line, "]: [")
			if len(parts) == 2 {
				add(strings.TrimSuffix(parts[1], "]"))
			}
		}
	}
	// Only use resolv.conf entries if they are real reachable addresses.
	if b, e := os.ReadFile("/etc/resolv.conf"); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			parts := strings.Fields(line)
			if len(parts) == 2 && parts[0] == "nameserver" {
				add(parts[1])
			}
		}
	}
	return out
}

// Resolve through Android-provided DNS when available. If Android exposes no
// resolver to this root service, use verified DNS-over-HTTPS with bootstrap IPs.
// This does not bypass network-level blocks or VPN routing restrictions.
func dohIPs(ctx context.Context, host string) ([]net.IP, error) {
	endpoints := []struct{ name, ip string }{{"cloudflare-dns.com", "1.1.1.1"}, {"dns.google", "8.8.8.8"}}
	var last error
	for _, ep := range endpoints {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: trustRoots(), MinVersion: tls.VersionTLS12}, DialContext: func(c context.Context, n, a string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(c, "tcp", net.JoinHostPort(ep.ip, "443"))
		}}
		c := &http.Client{Transport: tr, Timeout: 9 * time.Second}
		for _, typ := range []string{"A", "AAAA"} {
			u := "https://" + ep.name + "/dns-query?name=" + url.QueryEscape(host) + "&type=" + typ
			r, e := http.NewRequestWithContext(ctx, "GET", u, nil)
			if e != nil {
				return nil, e
			}
			r.Header.Set("Accept", "application/dns-json")
			resp, e := c.Do(r)
			if e != nil {
				last = e
				continue
			}
			var v struct {
				Status int `json:"Status"`
				Answer []struct {
					Data string `json:"data"`
				} `json:"Answer"`
			}
			e = json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&v)
			resp.Body.Close()
			if e != nil {
				last = e
				continue
			}
			if resp.StatusCode != 200 || v.Status != 0 {
				last = fmt.Errorf("DoH HTTP %d, DNS status %d", resp.StatusCode, v.Status)
				continue
			}
			ips := []net.IP{}
			for _, a := range v.Answer {
				if ip := net.ParseIP(a.Data); ip != nil {
					ips = append(ips, ip)
				}
			}
			if len(ips) > 0 {
				return ips, nil
			}
		}
	}
	return nil, fmt.Errorf("DNS-over-HTTPS unavailable: %v", last)
}
func androidDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	d := &net.Dialer{Timeout: 9 * time.Second}
	if net.ParseIP(host) != nil {
		return d.DialContext(ctx, network, address)
	}
	servers := androidDNS()
	var last error
	for _, server := range servers {
		server := server
		resolver := &net.Resolver{PreferGo: true, Dial: func(c context.Context, n, a string) (net.Conn, error) {
			return d.DialContext(c, "udp", net.JoinHostPort(server, "53"))
		}}
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ips, e := resolver.LookupIPAddr(rctx, host)
		cancel()
		if e != nil {
			last = e
			continue
		}
		for _, ip := range ips {
			conn, e := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.IP.String(), port))
			if e == nil {
				return conn, nil
			}
			last = e
		}
	}
	ips, e := dohIPs(ctx, host)
	if e != nil {
		return nil, fmt.Errorf("DNS resolution failed for %s: %v (system DNS: %v)", host, e, last)
	}
	for _, ip := range ips {
		conn, e := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if e == nil {
			return conn, nil
		}
		last = e
	}
	return nil, fmt.Errorf("DNS resolved %s but connection failed: %v", host, last)
}
func req(method, raw string, body io.Reader) (*http.Request, error) {
	r, e := http.NewRequest(method, raw, body)
	if e != nil {
		return nil, e
	}
	r.Header.Set("User-Agent", ua)
	r.Header.Set("Accept", "application/json, text/plain, */*")
	r.Header.Set("Accept-Language", lang)
	r.Header.Set("X-BL", lang)
	r.Header.Set("Origin", "https://gofile.io")
	r.Header.Set("Referer", "https://gofile.io/")
	return r, nil
}
func jsonout(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	jsonout(w, map[string]string{"error": msg})
}
func getToken() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && time.Since(s.tokenAt) < 12*time.Hour {
		return s.token, nil
	}
	if time.Now().Before(s.cooldown) {
		return "", fmt.Errorf("rate limited; wait before retry")
	}
	r, e := req("POST", "https://api.gofile.io/accounts", nil)
	if e != nil {
		return "", e
	}
	res, e := client.Do(r)
	if e != nil {
		return "", e
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 100000))
	if res.StatusCode == 429 {
		s.cooldown = time.Now().Add(5 * time.Minute)
	}
	if res.StatusCode != 200 && res.StatusCode != 201 {
		return "", fmt.Errorf("guest API HTTP %d: %s", res.StatusCode, string(b))
	}
	var v struct {
		Status string `json:"status"`
		Data   struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &v) != nil || v.Data.Token == "" {
		return "", fmt.Errorf("guest API returned no token: %.160s", b)
	}
	s.token = v.Data.Token
	s.tokenAt = time.Now()
	return s.token, nil
}
func websiteToken(tok string) string {
	salt := os.Getenv("GOFILE_WT_SALT")
	if salt == "" {
		salt = "12af056dacea0b"
	}
	s := fmt.Sprintf("%s::%s::%s::%d::%s", ua, lang, tok, time.Now().Unix()/14400, salt)
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
func contents(id, token string) ([]Item, error) {
	q := url.Values{"cache": {"true"}, "contentFilter": {""}, "page": {"1"}, "pageSize": {"1000"}, "sortField": {"name"}, "sortDirection": {"1"}}
	r, e := req("GET", "https://api.gofile.io/contents/"+url.PathEscape(id)+"?"+q.Encode(), nil)
	if e != nil {
		return nil, e
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-Website-Token", websiteToken(token))
	res, e := client.Do(r)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if e != nil {
		return nil, e
	}
	if res.StatusCode == 429 {
		s.mu.Lock()
		s.cooldown = time.Now().Add(5 * time.Minute)
		s.mu.Unlock()
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("Gofile API HTTP %d: %.260s", res.StatusCode, b)
	}
	var envelope struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	if e = json.Unmarshal(b, &envelope); e != nil {
		return nil, fmt.Errorf("Gofile returned invalid JSON: %w", e)
	}
	if envelope.Status != "ok" {
		return nil, fmt.Errorf("Gofile API status %q: %.260s", envelope.Status, b)
	}
	var data map[string]json.RawMessage
	if e = json.Unmarshal(envelope.Data, &data); e != nil {
		return nil, fmt.Errorf("Unexpected API data format: %w", e)
	}
	out := []Item{}
	parse := func(key string, v json.RawMessage) error {
		var item struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Type       string `json:"type"`
			Size       int64  `json:"size"`
			Link       string `json:"link"`
			DirectLink string `json:"directLink"`
		}
		if e := json.Unmarshal(v, &item); e != nil {
			return e
		}
		if item.ID == "" {
			item.ID = key
		}
		if item.Link == "" {
			item.Link = item.DirectLink
		}
		if item.Name == "" {
			item.Name = item.ID
		}
		if item.Type == "" {
			if item.Link != "" {
				item.Type = "file"
			} else {
				item.Type = "folder"
			}
		}
		if item.Type != "file" && item.Type != "folder" {
			return fmt.Errorf("unsupported content type %q", item.Type)
		}
		out = append(out, Item{ID: item.ID, Name: item.Name, Type: item.Type, Size: item.Size, Link: item.Link})
		return nil
	}
	raw, hasChildren := data["children"]
	if hasChildren && string(raw) != "null" {
		var obj map[string]json.RawMessage
		if e := json.Unmarshal(raw, &obj); e == nil && obj != nil {
			for key, v := range obj {
				if e := parse(key, v); e != nil {
					return nil, fmt.Errorf("Malformed child %s: %w", key, e)
				}
			}
		} else {
			var arr []json.RawMessage
			if e := json.Unmarshal(raw, &arr); e != nil {
				return nil, fmt.Errorf("Unexpected children format: %.200s", raw)
			}
			for i, v := range arr {
				if e := parse(strconv.Itoa(i), v); e != nil {
					return nil, fmt.Errorf("Malformed child %d: %w", i, e)
				}
			}
		}
	} else {
		// Gofile sometimes returns the file object itself for /contents/{id}.
		// Do not fabricate a folder or assume that missing children means empty.
		var meta struct {
			Type       string `json:"type"`
			Name       string `json:"name"`
			Link       string `json:"link"`
			DirectLink string `json:"directLink"`
		}
		if e := json.Unmarshal(envelope.Data, &meta); e != nil {
			return nil, e
		}
		if meta.Type != "file" && !(meta.Type == "" && (meta.Link != "" || meta.DirectLink != "")) {
			return nil, fmt.Errorf("API returned no children and did not identify a file (type=%q; fields: %s)", meta.Type, strings.Join(sortedKeys(data), ", "))
		}
		if e := parse(id, envelope.Data); e != nil {
			return nil, fmt.Errorf("Malformed file object: %w", e)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("Gofile returned no items (type/fields: %s)", strings.Join(sortedKeys(data), ", "))
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}
func sortedKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Website-only experimental extractor. It never contacts api.gofile.io.
// Gofile currently renders most folders using JavaScript; a static page may
// therefore contain no file metadata. Report that clearly instead of guessing.
var mediaURL = regexp.MustCompile(`https?://[A-Za-z0-9.-]+\.gofile\.io/download/[A-Za-z0-9%_./()~-]+`)
var jsonFile = regexp.MustCompile(`(?s)"name"\s*:\s*"([^"\\]{1,300})".{0,700}?"link"\s*:\s*"(https?[^"\\]+)"`)

func websiteFolder(code string) ([]Item, error) {
	page := "https://gofile.io/d/" + url.PathEscape(code)
	r, e := req("GET", page, nil)
	if e != nil {
		return nil, e
	}
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	resp, e := client.Do(r)
	if e != nil {
		return nil, fmt.Errorf("Website connection failed: %w", e)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Gofile website returned HTTP %d", resp.StatusCode)
	}
	body, e := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if e != nil {
		return nil, e
	}
	raw := htmlpkg.UnescapeString(string(body))
	raw = strings.ReplaceAll(raw, `\/`, `/`)
	seen := map[string]bool{}
	out := []Item{}
	add := func(name, link string) {
		u, e := url.Parse(link)
		if e != nil || u.Scheme != "https" || !strings.HasSuffix(u.Hostname(), ".gofile.io") || !strings.HasPrefix(u.Path, "/download/") || seen[link] {
			return
		}
		seen[link] = true
		if name == "" {
			name = path.Base(u.Path)
		}
		id := fmt.Sprintf("web-%d", len(out)+1)
		out = append(out, Item{ID: id, Name: name, Type: "file", Link: link})
	}
	for _, m := range jsonFile.FindAllStringSubmatch(raw, -1) {
		add(m[1], m[2])
	}
	for _, link := range mediaURL.FindAllString(raw, -1) {
		add("", link)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("Website loaded, but no download links were embedded in HTML. Gofile loads the folder via JavaScript; static scraping cannot read this folder without a browser-based extractor")
	}
	return out, nil
}
func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, html)
	})
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		jsonout(w, map[string]string{"status": "ok", "version": "1.0.0"})
	})
	mux.HandleFunc("/api/network", func(w http.ResponseWriter, r *http.Request) {
		jsonout(w, map[string]interface{}{"dnsServers": androidDNS(), "hint": "DNS discovery is automatic; if empty, reconnect your VPN or network"})
	})
	mux.HandleFunc("/api/load", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			fail(w, 405, "POST required")
			return
		}
		var in struct {
			URL   string `json:"url"`
			Token string `json:"token"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in) != nil {
			fail(w, 400, "Invalid JSON")
			return
		}
		u, e := url.Parse(in.URL)
		if e != nil || u.Scheme != "https" || u.Hostname() != "gofile.io" || !strings.HasPrefix(u.Path, "/d/") {
			fail(w, 400, "Enter https://gofile.io/d/... link")
			return
		}
		id := path.Base(u.Path)
		if id == "" || id == "d" {
			fail(w, 400, "Invalid folder ID")
			return
		}
		items, e := websiteFolder(id)
		if e != nil {
			siteErr := e
			token := strings.TrimSpace(in.Token)
			if token == "" {
				token, e = getToken()
				if e != nil {
					fail(w, 502, fmt.Sprintf("Website extraction: %v; dynamic folder API guest session: %v", siteErr, e))
					return
				}
			}
			items, e = contents(id, token)
			if e != nil {
				fail(w, 502, fmt.Sprintf("Website extraction: %v; dynamic folder API: %v", siteErr, e))
				return
			}
			s.mu.Lock()
			s.token = token
			s.tokenAt = time.Now()
			s.mu.Unlock()
		}
		s.mu.Lock()
		s.items = map[string]Item{}
		for _, it := range items {
			s.items[it.ID] = it
		}
		s.mu.Unlock()
		jsonout(w, items)
	})
	mux.HandleFunc("/api/folder", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		s.mu.Lock()
		it, ok := s.items[id]
		s.mu.Unlock()
		if !ok || it.Type != "folder" {
			fail(w, 404, "Unknown folder")
			return
		}
		s.mu.Lock()
		tok := s.token
		s.mu.Unlock()
		if tok == "" {
			fail(w, 502, "Folder navigation requires an API session")
			return
		}
		items, e := contents(id, tok)
		if e != nil {
			fail(w, 502, e.Error())
			return
		}
		s.mu.Lock()
		for _, v := range items {
			s.items[v.ID] = v
		}
		s.mu.Unlock()
		jsonout(w, items)
	})
	mux.HandleFunc("/api/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			fail(w, 405, "POST required")
			return
		}
		s.mu.Lock()
		s.selected = ""
		s.items = map[string]Item{}
		s.token = ""
		s.tokenAt = time.Time{}
		for _, cancel := range s.active {
			cancel()
		}
		s.mu.Unlock()
		jsonout(w, map[string]bool{"reset": true})
	})
	mux.HandleFunc("/api/select", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			fail(w, 405, "POST required")
			return
		}
		id := r.URL.Query().Get("id")
		s.mu.Lock()
		it, ok := s.items[id]
		if ok && it.Type == "file" && it.Link != "" {
			s.selected = id
		}
		s.mu.Unlock()
		if !ok || it.Type != "file" || it.Link == "" {
			fail(w, 400, "No streamable file URL")
			return
		}
		jsonout(w, map[string]string{"url": "http://127.0.0.1:8765/video", "name": it.Name})
	})
	mux.HandleFunc("/video", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		it, ok := s.items[s.selected]
		tok := s.token
		s.mu.Unlock()
		if !ok {
			fail(w, 404, "Select a file first")
			return
		}
		u, e := url.Parse(it.Link)
		if e != nil || u.Scheme != "https" || !(strings.HasSuffix(u.Hostname(), ".gofile.io") || u.Hostname() == "gofile.io") {
			fail(w, 502, "Invalid Gofile media host")
			return
		}
		up, e := req(r.Method, it.Link, nil)
		if e != nil {
			fail(w, 502, e.Error())
			return
		}
		ctx, cancel := context.WithCancel(r.Context())
		s.mu.Lock()
		s.nextStream++
		streamID := s.nextStream
		s.active[streamID] = cancel
		s.mu.Unlock()
		defer func() { cancel(); s.mu.Lock(); delete(s.active, streamID); s.mu.Unlock() }()
		up = up.WithContext(ctx)
		if tok != "" {
			up.Header.Set("Cookie", "accountToken="+tok)
		}
		up.Header.Set("Referer", "https://gofile.io/")
		if h := r.Header.Get("Range"); h != "" {
			up.Header.Set("Range", h)
		}
		res, e := client.Do(up)
		if e != nil {
			fail(w, 502, e.Error())
			return
		}
		defer res.Body.Close()
		if res.StatusCode == http.StatusOK && strings.Contains(res.Header.Get("Content-Type"), "text/html") {
			fail(w, 502, "Upstream returned HTML, not video")
			return
		}
		for _, k := range []string{"Content-Type", "Content-Length", "Content-Range", "Accept-Ranges", "ETag", "Last-Modified"} {
			if v := res.Header.Get(k); v != "" {
				w.Header().Set(k, v)
			}
		}
		w.WriteHeader(res.StatusCode)
		io.Copy(w, res.Body)
	})
	log.Println("Gofile Bridge v1.0.0 listening on 127.0.0.1:8765")
	ln, e := net.Listen("tcp", "127.0.0.1:8765")
	if e != nil {
		log.Fatal(e)
	}
	log.Fatal(http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Loopback-only service: permit KernelSU WebView's varying origin, including null.
		// No cookies or credentialed CORS responses are used.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Private-Network", "true")
		w.Header().Set("Access-Control-Max-Age", "600")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		mux.ServeHTTP(w, r)
	})))
}
func init() { _ = strconv.Itoa }

const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"><title>Gofile Bridge</title><style>
:root{color-scheme:dark;font-family:system-ui,-apple-system,Roboto,sans-serif}*{box-sizing:border-box}body{margin:0;background:#0c1220;color:#f1f5f9;padding:env(safe-area-inset-top) 16px 36px;line-height:1.45}main{max-width:650px;margin:20px auto}h1{font-size:1.5rem;margin:0}p{margin:7px 0 18px;color:#94a3b8;font-size:.9rem}.panel{border:1px solid #334155;border-radius:17px;padding:16px;margin:16px 0;background:#141f32}label{display:block;font-size:.88rem;color:#cbd5e1;margin:0 0 8px}input,button{font:inherit;width:100%;border-radius:10px;min-height:46px}input{border:1px solid #475569;background:#0b1425;color:#fff;padding:11px;min-width:0}button{border:0;background:#3b82f6;color:white;font-weight:650;padding:10px 14px;cursor:pointer}button:disabled{opacity:.55;cursor:wait}button.secondary{background:#27364d}details{margin:12px 0;color:#94a3b8}details input{margin-top:8px}#status{min-height:22px;white-space:pre-wrap;overflow-wrap:anywhere}#status.error{color:#fca5a5}#status.ok{color:#86efac}.entry{display:flex;align-items:center;gap:12px;width:100%;text-align:left;background:#202e43;margin:7px 0;overflow-wrap:anywhere}.entry span{min-width:0;flex:1}.entry small{display:block;color:#a8b7cd;font-size:.78rem;font-weight:400}#stream[hidden],#back[hidden]{display:none}.url{overflow-wrap:anywhere;font-size:.85rem;color:#93c5fd}footer{text-align:center;color:#71829c;font-size:.75rem;margin-top:25px}#back{margin-bottom:10px}#files:empty:after{content:'No files loaded';display:block;color:#8191a8;text-align:center;padding:15px}button:focus-visible,input:focus-visible{outline:2px solid #93c5fd;outline-offset:2px}
</style></head><body><main><header><h1>Gofile Bridge</h1><p>Website + dynamic API fallback · v1.0.0</p></header><section class="panel"><label for="url">Gofile folder link</label><input id="url" inputmode="url" autocapitalize="off" spellcheck="false" placeholder="https://gofile.io/d/..."><details><summary>Optional Gofile account token</summary><input id="token" type="password" autocomplete="off" placeholder="Leave empty for guest access"></details><button id="load">Load Files</button><button id="reset" class="secondary" style="margin-top:10px">Reset &amp; Stop Proxy</button><p id="status" role="status" aria-live="polite"></p></section><section class="panel"><button id="back" class="secondary" hidden>← Back</button><div id="files"></div></section><section class="panel" id="stream" hidden><strong>Selected video</strong><p id="filename"></p><div class="url">http://127.0.0.1:8765/video</div><button id="copy">Copy VLC Link</button></section><footer>Zockerwolf76</footer></main><script>
'use strict';const $=id=>document.getElementById(id),stack=[];let busy=false;function status(t,kind=''){const e=$('status');e.textContent=t;e.className=kind}async function api(u,o){const r=await fetch('http://127.0.0.1:8765'+u,o);let data;try{data=await r.json()}catch{throw Error('Invalid server response (HTTP '+r.status+')')}if(!r.ok)throw Error(data.error||'HTTP '+r.status);return data}function show(items){const root=$('files');root.replaceChildren();$('back').hidden=!stack.length;for(const item of items){const b=document.createElement('button');b.className='entry';const icon=document.createElement('span');icon.style.flex='none';icon.style.width='26px';icon.textContent=item.type==='folder'?'📁':'🎬';const txt=document.createElement('span');txt.textContent=item.name||'Unnamed';if(item.size&&item.type!=='folder'){const sm=document.createElement('small');sm.textContent=(item.size/1073741824).toFixed(2)+' GiB';txt.appendChild(sm)}b.append(icon,txt);b.onclick=async()=>{if(busy)return;busy=true;b.disabled=true;status('Loading…');try{if(item.type==='folder'){const children=await api('/api/folder?id='+encodeURIComponent(item.id));stack.push(items);show(children);$('stream').hidden=true}else{await api('/api/select?id='+encodeURIComponent(item.id),{method:'POST'});$('filename').textContent=item.name;$('stream').hidden=false;status('Proxy selected. Open the VLC link to test playback.','ok')}}catch(e){status(e.message,'error')}finally{busy=false;b.disabled=false}};root.appendChild(b)}}$('back').onclick=()=>{if(stack.length){show(stack.pop());$('stream').hidden=true;status('')}};$('load').onclick=async()=>{if(busy)return;busy=true;$('load').disabled=true;status('Loading folder…');$('stream').hidden=true;$('files').replaceChildren();stack.length=0;try{const items=await api('/api/load',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:$('url').value.trim(),token:$('token').value.trim()})});if(!items.length)throw Error('Gofile returned no files. This is not a successful load.');show(items);status(items.length+' item(s) loaded','ok')}catch(e){status(e instanceof TypeError?'Cannot reach local bridge from KernelSU WebUI. Open http://127.0.0.1:8765/ in Chrome to test.':e.message,'error')}finally{busy=false;$('load').disabled=false}};$('reset').onclick=async()=>{if(busy)return;busy=true;$('reset').disabled=true;try{await api('/api/reset',{method:'POST'});$('url').value='';$('token').value='';$('files').replaceChildren();$('stream').hidden=true;$('filename').textContent='';stack.length=0;$('back').hidden=true;status('Reset complete. Active proxy streams stopped.','ok')}catch(e){status(e.message,'error')}finally{busy=false;$('reset').disabled=false}};$('copy').onclick=async()=>{const link='http://127.0.0.1:8765/video';try{await navigator.clipboard.writeText(link);status('VLC link copied','ok')}catch{status('Copy unavailable: '+link,'error')}};
</script></body></html>`
