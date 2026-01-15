package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cheggaaa/pb"
	"github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/compress/zstd"
	"github.com/valyala/fasthttp"
)

const (
	userAgent = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0"
)

type fuzzRequest struct {
	raw     string
	method  string
	path    string
	proto   string
	version string
	desc    string
	valid   bool
	http11  bool
}

type requestJSON struct {
	Raw     string `json:"raw"`
	Method  string `json:"method,omitempty"`
	Path    string `json:"path,omitempty"`
	Proto   string `json:"proto,omitempty"`
	Version string `json:"version,omitempty"`
	Desc    string `json:"desc,omitempty"`
	Valid   bool   `json:"valid"`
}

type headerKV struct {
	K string `json:"k"`
	V string `json:"v"`
}

type responseJSON struct {
	Proto      string     `json:"proto,omitempty"`
	StatusCode int        `json:"status_code,omitempty"`
	Status     string     `json:"status,omitempty"`
	Headers    []headerKV `json:"headers,omitempty"`
	BodyB64    string     `json:"body_b64,omitempty"`
	Body       []byte     `json:"-"`
}

type surveyRecord struct {
	Domain  string        `json:"domain"`
	Request requestJSON   `json:"request"`
	HTTP11  bool          `json:"http11"`
	Error   string        `json:"error,omitempty"`
	Resp    *responseJSON `json:"response,omitempty"`
}

type surveyParquetRow struct {
	Domain         string
	RequestRaw     string
	RequestMethod  string
	RequestPath    string
	RequestProto   string
	RequestVersion string
	RequestDesc    string
	RequestValid   bool
	HTTP11         bool
	Error          string

	RespProto       string
	RespStatusCode  int32
	RespStatus      string
	RespHeadersJSON string
	RespBody        []byte
}

func toSurveyParquetRow(rec surveyRecord) (surveyParquetRow, error) {
	row := surveyParquetRow{
		Domain:         rec.Domain,
		RequestRaw:     rec.Request.Raw,
		RequestMethod:  rec.Request.Method,
		RequestPath:    rec.Request.Path,
		RequestProto:   rec.Request.Proto,
		RequestVersion: rec.Request.Version,
		RequestDesc:    rec.Request.Desc,
		RequestValid:   rec.Request.Valid,
		HTTP11:         rec.HTTP11,
		Error:          rec.Error,
	}

	if rec.Resp == nil {
		return row, nil
	}

	row.RespProto = rec.Resp.Proto
	row.RespStatusCode = int32(rec.Resp.StatusCode)
	row.RespStatus = rec.Resp.Status

	if len(rec.Resp.Headers) > 0 {
		b, err := json.Marshal(rec.Resp.Headers)
		if err != nil {
			return row, err
		}
		row.RespHeadersJSON = string(b)
	}

	if len(rec.Resp.Body) > 0 {
		row.RespBody = append(row.RespBody[:0], rec.Resp.Body...)
	}

	return row, nil
}

func main() {
	csvParam := flag.String("f", "", "path to domains file (CSV or plain text)")
	columnFlag := flag.String("C", "", "1-based column number containing domains (default: auto-detect)")
	outputDir := flag.String("o", "responses", "output directory for response files")
	requestsFlag := flag.String("r", "data/request_set.txt", "path to request set file")
	concurrency := flag.Int("c", 100, "maximum number of concurrent domains to process")
	perDomainWorkers := flag.Int("w", 10, "concurrent requests per domain")
	timeout := flag.Duration("t", 10*time.Second, "timeout for each request")
	proxyFlag := flag.String("p", "", "proxy URL (e.g., http://127.0.0.1:8080)")
	includeBody := flag.Bool("B", false, "include response body in output (slower)")
	outputFormat := flag.String("format", "jsonl", "output format: jsonl or parquet")
	cacheEnabled := flag.Bool("cache", true, "enable on-disk caching")
	cacheDir := flag.String("cache-dir", ".cache/httpfuzz/survey", "path to cache directory")
	flag.Parse()

	if strings.TrimSpace(*csvParam) == "" {
		candidates := []string{
			"data/targets.csv.resolved.txt",
			"data/targets.csv.resolved.csv",
			"data/targets.txt",
			"data/targets.csv",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				*csvParam = c
				break
			}
		}
	}

	var colOverride *int
	if strings.TrimSpace(*columnFlag) != "" {
		colIdx, err := strconv.Atoi(*columnFlag)
		if err != nil || colIdx < 1 {
			log.Fatalf("invalid column number: %s", *columnFlag)
		}
		colIdx--
		colOverride = &colIdx
	}

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		log.Fatalf("failed to create output dir %s: %v", *outputDir, err)
	}

	domainList, err := parseDomainsFile(*csvParam, colOverride)
	if err != nil {
		log.Fatalf("failed to parse domains file: %v", err)
	}

	fuzzLines, err := readFuzzFile(*requestsFlag)
	if err != nil {
		log.Fatalf("failed to read fuzz file: %v", err)
	}

	if *cacheEnabled {
		if err := os.MkdirAll(*cacheDir, 0o755); err != nil {
			log.Fatalf("failed to create cache dir %s: %v", *cacheDir, err)
		}
		if err := loadDNSCache(filepath.Join(*cacheDir, "dns.json")); err != nil {
			log.Printf("failed to load dns cache: %v", err)
		}
	}

	totalRequests := len(domainList) * len(fuzzLines)
	bar := pb.StartNew(totalRequests)

	var wg sync.WaitGroup
	sem := make(chan struct{}, *concurrency)

	var proxyURL *url.URL
	if strings.TrimSpace(*proxyFlag) != "" {
		parsed, err := url.Parse(*proxyFlag)
		if err != nil {
			log.Fatalf("invalid proxy URL: %v", err)
		}
		if parsed.Scheme == "" || parsed.Host == "" {
			log.Fatalf("invalid proxy URL: %s", *proxyFlag)
		}
		proxyURL = parsed
	}

	fastClient := &fasthttp.Client{
		Name:                     userAgent,
		NoDefaultUserAgentHeader: true,
		ReadTimeout:              *timeout,
		WriteTimeout:             *timeout,
		MaxConnsPerHost:          max(1, *perDomainWorkers),
		MaxIdleConnDuration:      2 * time.Second,
	}
	if proxyURL != nil {
		if proxyURL.Scheme != "http" {
			log.Fatalf("unsupported proxy scheme: %s", proxyURL.Scheme)
		}
		fastClient.Dial = dialViaHTTPProxy(proxyURL, *timeout)
		fastClient.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	} else {
		fastClient.Dial = dialDirect(*timeout)
	}

	for _, domain := range domainList {
		wg.Add(1)
		sem <- struct{}{}
		go func(d string) {
			defer wg.Done()
			defer func() { <-sem }()

			processDomain(d, fuzzLines, *outputDir, *outputFormat, *cacheEnabled, *cacheDir, fastClient, proxyURL, *timeout, *perDomainWorkers, *includeBody, bar)
		}(domain)
	}

	wg.Wait()
	bar.Finish()

	if *cacheEnabled {
		if err := saveDNSCache(filepath.Join(*cacheDir, "dns.json")); err != nil {
			log.Printf("failed to save dns cache: %v", err)
		}
	}
}

func dialDirect(timeout time.Duration) func(addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return func(addr string) (net.Conn, error) {
		return safeDialAddr(d, addr, timeout)
	}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

type dnsCacheEntry struct {
	ips []net.IP
}

var dnsCache sync.Map

func loadDNSCache(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var file map[string][]string
	if err := json.Unmarshal(b, &file); err != nil {
		return err
	}
	for host, ips := range file {
		if strings.TrimSpace(host) == "" {
			continue
		}
		var out []net.IP
		for _, ipStr := range ips {
			ip := net.ParseIP(strings.TrimSpace(ipStr))
			if ip == nil || !isPublicIP(ip) {
				continue
			}
			out = append(out, ip)
		}
		if len(out) == 0 {
			continue
		}
		dnsCache.Store(host, dnsCacheEntry{ips: out})
	}
	return nil
}

func saveDNSCache(path string) error {
	out := make(map[string][]string)
	dnsCache.Range(func(k, v any) bool {
		host, ok := k.(string)
		if !ok || strings.TrimSpace(host) == "" {
			return true
		}
		e := v.(dnsCacheEntry)
		if len(e.ips) == 0 {
			return true
		}
		ips := make([]string, 0, len(e.ips))
		for _, ip := range e.ips {
			if ip == nil || !isPublicIP(ip) {
				continue
			}
			ips = append(ips, ip.String())
		}
		if len(ips) > 0 {
			out[host] = ips
		}
		return true
	})

	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	return ip.IsGlobalUnicast()
}

func resolvePublicIPs(host string, timeout time.Duration) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !isPublicIP(ip) {
			return nil, fmt.Errorf("blocked non-public IP: %s", host)
		}
		return []net.IP{ip}, nil
	}

	if v, ok := dnsCache.Load(host); ok {
		e := v.(dnsCacheEntry)
		if len(e.ips) == 0 {
			return nil, fmt.Errorf("no public IPs for host: %s", host)
		}
		return e.ips, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		dnsCache.Store(host, dnsCacheEntry{ips: nil})
		return nil, err
	}

	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if isPublicIP(a.IP) {
			ips = append(ips, a.IP)
		}
	}

	dnsCache.Store(host, dnsCacheEntry{ips: ips})
	if len(ips) == 0 {
		return nil, fmt.Errorf("no public IPs for host: %s", host)
	}
	return ips, nil
}

func safeDialAddr(d *net.Dialer, addr string, timeout time.Duration) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	ips, err := resolvePublicIPs(host, timeout)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var lastErr error
	for _, ip := range ips {
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("failed dialing %s", addr)
	}
	return nil, lastErr
}

func dialViaHTTPProxy(proxyURL *url.URL, timeout time.Duration) func(addr string) (net.Conn, error) {
	proxyHost := proxyURL.Host
	if !strings.Contains(proxyHost, ":") {
		proxyHost = proxyHost + ":80"
	}

	d := &net.Dialer{Timeout: timeout}
	return func(addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err == nil {
			if ip := net.ParseIP(host); ip != nil && !isPublicIP(ip) {
				return nil, fmt.Errorf("blocked non-public IP: %s", host)
			}
		}

		conn, err := d.Dial("tcp", proxyHost)
		if err != nil {
			return nil, err
		}

		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			conn.Close()
			return nil, err
		}

		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", addr, addr, userAgent)
		if _, err := conn.Write([]byte(connectReq)); err != nil {
			conn.Close()
			return nil, err
		}

		reader := bufio.NewReader(conn)
		statusLine, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}
		fields := strings.Fields(statusLine)
		if len(fields) < 2 || fields[1] != "200" {
			for {
				line, err := reader.ReadString('\n')
				if err != nil || line == "\r\n" {
					break
				}
			}
			conn.Close()
			return nil, fmt.Errorf("proxy CONNECT failed: %s", strings.TrimSpace(statusLine))
		}
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}

		_ = conn.SetDeadline(time.Time{})

		if reader.Buffered() > 0 {
			return &bufferedConn{Conn: conn, r: reader}, nil
		}
		return conn, nil
	}
}

func parseDomainsFile(filename string, colOverride *int) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rows [][]string
	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(record) == 0 {
			continue
		}
		rows = append(rows, record)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("no rows found")
	}

	startIdx := 0
	var colIdx int
	if colOverride != nil {
		colIdx = *colOverride
		if colIdx < 0 {
			colIdx = 0
		}
		if looksLikeHeader(rows[0]) && len(rows) > 1 {
			startIdx = 1
		}
	} else {
		colIdx, startIdx = chooseDomainColumn(rows)
	}

	seen := make(map[string]struct{}, len(rows))
	var domains []string
	for _, row := range rows[startIdx:] {
		if colIdx >= len(row) {
			continue
		}
		if d, ok := normalizeDomainCandidate(row[colIdx]); ok {
			if _, exists := seen[d]; exists {
				continue
			}
			seen[d] = struct{}{}
			domains = append(domains, d)
		}
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains found")
	}
	return domains, nil
}

func readFuzzFile(filename string) ([]fuzzRequest, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(content), "\n")
	var fuzzLines []fuzzRequest
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			fr := fuzzRequest{raw: trimmed}
			parts := strings.SplitN(trimmed, " ", 5)
			if len(parts) == 5 {
				fr.method = parts[0]
				fr.path = parts[1]
				fr.proto = parts[2]
				fr.version = parts[3]
				fr.desc = parts[4]
				fr.valid = true
				fr.http11 = fr.proto == "HTTP" && fr.version == "1.1"
			}
			fuzzLines = append(fuzzLines, fr)
		}
	}
	return fuzzLines, nil
}

func processDomain(domain string, fuzzLines []fuzzRequest, outputDir string, outputFormat string, cacheEnabled bool, cacheDir string, client *fasthttp.Client, proxyURL *url.URL, timeout time.Duration, workers int, includeBody bool, bar *pb.ProgressBar) {
	// Sanitize domain name for filename
	safeName := strings.ReplaceAll(domain, "/", "_")
	safeName = strings.ReplaceAll(safeName, ":", "_")
	outputPath := filepath.Join(outputDir, safeName)
	if strings.EqualFold(strings.TrimSpace(outputFormat), "parquet") {
		outputPath = outputPath + ".parquet"
	}

	file, err := os.Create(outputPath)
	if err != nil {
		log.Printf("error creating file for %s: %v", domain, err)
		return
	}
	defer file.Close()

	var cache map[string][]byte
	if cacheEnabled {
		cacheFile := cacheRecordsPath(cacheDir, safeName, includeBody)
		cache, _ = loadSurveyRecordCache(cacheFile)
		if cache == nil {
			cache = make(map[string][]byte)
		}
	}

	if workers < 1 {
		workers = 1
	}

	tasks := make(chan fuzzRequest)
	results := make(chan surveyRecord, workers*2)

	var workerWG sync.WaitGroup
	for i := 0; i < workers; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for fr := range tasks {
				parquetOutput := strings.EqualFold(strings.TrimSpace(outputFormat), "parquet")
				writeBodyB64 := cacheEnabled || !parquetOutput
				results <- executeFuzz(domain, fr, client, proxyURL, timeout, includeBody, writeBodyB64)
				bar.Increment()
			}
		}()
	}

	missing := make([]fuzzRequest, 0, len(fuzzLines))
	if cacheEnabled {
		for _, fr := range fuzzLines {
			if line, ok := cache[fr.raw]; ok && len(line) > 0 {
				continue
			}
			missing = append(missing, fr)
		}
	} else {
		missing = append(missing, fuzzLines...)
	}

	go func() {
		for _, fr := range missing {
			tasks <- fr
		}
		close(tasks)
		workerWG.Wait()
		close(results)
	}()

	switch strings.ToLower(strings.TrimSpace(outputFormat)) {
	case "parquet":
		pqWriter := parquet.NewGenericWriter[surveyParquetRow](file, parquet.Compression(&zstd.Codec{}))
		defer pqWriter.Close()

		for _, fr := range fuzzLines {
			if !cacheEnabled {
				break
			}
			line := cache[fr.raw]
			if len(line) == 0 {
				continue
			}
			rec, err := surveyRecordFromCacheJSONLine(line, includeBody)
			if err != nil {
				continue
			}
			if includeBody {
				hydrateBodyBytes(&rec)
			}
			row, err := toSurveyParquetRow(rec)
			if err != nil {
				continue
			}
			_, _ = pqWriter.Write([]surveyParquetRow{row})
			bar.Increment()
		}

		for rec := range results {
			row, err := toSurveyParquetRow(rec)
			if err != nil {
				continue
			}
			_, _ = pqWriter.Write([]surveyParquetRow{row})

			if cacheEnabled {
				cacheFile := cacheRecordsPath(cacheDir, safeName, includeBody)
				line := mustMarshalJSON(rec)
				_ = appendCacheLine(cacheFile, line)
				cache[rec.Request.Raw] = append([]byte(nil), line...)
			}
		}
	default:
		writer := bufio.NewWriter(file)
		if cacheEnabled {
			for _, fr := range fuzzLines {
				line := cache[fr.raw]
				if len(line) == 0 {
					continue
				}
				writer.Write(line)
				writer.WriteByte('\n')
				bar.Increment()
			}
		}
		for rec := range results {
			res := mustMarshalJSON(rec)
			res = sanitizeJSONLLine(res)
			writer.Write(res)
			writer.WriteByte('\n')
			if cacheEnabled {
				cacheFile := cacheRecordsPath(cacheDir, safeName, includeBody)
				_ = appendCacheLine(cacheFile, res)
				cache[rec.Request.Raw] = append([]byte(nil), res...)
			}
		}
		writer.Flush()
	}
}

func cacheRecordsPath(cacheDir, safeName string, includeBody bool) string {
	name := safeName
	if includeBody {
		name = name + ".body"
	}
	return filepath.Join(cacheDir, "records", name+".jsonl")
}

func loadSurveyRecordCache(path string) (map[string][]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string][]byte{}, nil
		}
		return nil, err
	}

	out := make(map[string][]byte)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec struct {
			Request struct {
				Raw string `json:"raw"`
			} `json:"request"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if strings.TrimSpace(rec.Request.Raw) == "" {
			continue
		}
		out[rec.Request.Raw] = []byte(line)
	}
	return out, nil
}

func appendCacheLine(path string, line []byte) error {
	if len(line) == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(line); err != nil {
		return err
	}
	if _, err := f.Write([]byte("\n")); err != nil {
		return err
	}
	return nil
}

func surveyRecordFromCacheJSONLine(line []byte, includeBody bool) (surveyRecord, error) {
	var rec surveyRecord
	if err := json.Unmarshal(line, &rec); err != nil {
		return surveyRecord{}, err
	}
	if includeBody {
		hydrateBodyBytes(&rec)
	}
	return rec, nil
}

func hydrateBodyBytes(rec *surveyRecord) {
	if rec == nil || rec.Resp == nil || len(rec.Resp.Body) > 0 || rec.Resp.BodyB64 == "" {
		return
	}
	b, err := base64.StdEncoding.DecodeString(rec.Resp.BodyB64)
	if err != nil || len(b) == 0 {
		return
	}
	rec.Resp.Body = b
}

func looksLikeHeader(row []string) bool {
	if len(row) == 0 {
		return false
	}
	tokens := []string{"domain", "domains", "host", "hostname", "fqdn", "url", "website", "site"}
	for _, cell := range row {
		c := strings.ToLower(strings.TrimSpace(cell))
		for _, t := range tokens {
			if c == t || strings.Contains(c, "domain") {
				return true
			}
		}
	}
	domainCount := 0
	for _, cell := range row {
		if _, ok := normalizeDomainCandidate(cell); ok {
			domainCount++
		}
	}
	return domainCount == 0
}

func chooseDomainColumn(rows [][]string) (int, int) {
	maxCols := 0
	for _, r := range rows {
		if len(r) > maxCols {
			maxCols = len(r)
		}
	}
	if maxCols == 0 {
		return 0, 0
	}

	startIdx := 0
	if looksLikeHeader(rows[0]) && len(rows) > 1 {
		for idx, cell := range rows[0] {
			c := strings.ToLower(strings.TrimSpace(cell))
			if c == "domain" || c == "domains" || c == "host" || c == "hostname" || c == "fqdn" || c == "url" || strings.Contains(c, "domain") {
				return idx, 1
			}
		}
		startIdx = 1
	}

	bestCol := 0
	bestScore := -1
	sampleEnd := startIdx + 250
	if sampleEnd > len(rows) {
		sampleEnd = len(rows)
	}

	for col := 0; col < maxCols; col++ {
		score := 0
		for _, row := range rows[startIdx:sampleEnd] {
			if col >= len(row) {
				continue
			}
			if _, ok := normalizeDomainCandidate(row[col]); ok {
				score++
			}
		}
		if score > bestScore {
			bestScore = score
			bestCol = col
		}
	}

	return bestCol, startIdx
}

func normalizeDomainCandidate(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	s = strings.Trim(s, `"'`)
	if s == "" {
		return "", false
	}

	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			if u.Host != "" {
				s = u.Host
			}
		}
	}

	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}

	if strings.HasPrefix(s, "[") {
		if end := strings.IndexByte(s, ']'); end > 0 {
			s = s[1:end]
			if ip := net.ParseIP(s); ip != nil {
				if !isPublicIP(ip) {
					return "", false
				}
				return strings.ToLower(s), true
			}
			return "", false
		}
	}

	if strings.Contains(s, ":") {
		host, _, err := net.SplitHostPort(s)
		if err == nil && host != "" {
			s = host
		} else {
			s = strings.SplitN(s, ":", 2)[0]
		}
	}

	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	s = strings.ToLower(s)
	if s == "" {
		return "", false
	}

	if ip := net.ParseIP(s); ip != nil {
		if !isPublicIP(ip) {
			return "", false
		}
		return s, true
	}

	if len(s) > 253 || !strings.Contains(s, ".") || strings.Contains(s, "..") {
		return "", false
	}
	if strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return "", false
	}

	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			continue
		}
		return "", false
	}

	return s, true
}

func executeFuzz(domain string, fr fuzzRequest, client *fasthttp.Client, proxyURL *url.URL, timeout time.Duration, includeBody bool, writeBodyB64 bool) surveyRecord {
	rec := surveyRecord{
		Domain: domain,
		Request: requestJSON{
			Raw:     fr.raw,
			Method:  fr.method,
			Path:    fr.path,
			Proto:   fr.proto,
			Version: fr.version,
			Desc:    fr.desc,
			Valid:   fr.valid,
		},
		HTTP11: fr.http11,
	}

	if !fr.valid {
		rec.Error = "invalid request line"
		return rec
	}

	if fr.http11 {
		targetURL := buildTargetURL(domain, fr.path)
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseRequest(req)
		defer fasthttp.ReleaseResponse(resp)

		req.Header.SetMethod(fr.method)
		req.SetRequestURI(targetURL)
		req.Header.SetUserAgent(userAgent)
		resp.SkipBody = !includeBody

		if err := client.DoRedirects(req, resp, 10); err != nil {
			rec.Error = err.Error()
			return rec
		}

		proto := resp.Header.Protocol()
		if len(proto) == 0 {
			proto = []byte("HTTP/1.1")
		}
		statusCode := resp.StatusCode()
		statusMsg := resp.Header.StatusMessage()
		if len(statusMsg) == 0 {
			statusMsg = []byte(fasthttp.StatusMessage(statusCode))
		}

		out := &responseJSON{
			Proto:      string(proto),
			StatusCode: statusCode,
			Status:     string(statusMsg),
		}
		resp.Header.VisitAll(func(k, v []byte) {
			out.Headers = append(out.Headers, headerKV{K: string(k), V: string(v)})
		})
		if includeBody {
			out.Body = append(out.Body[:0], resp.Body()...)
			if writeBodyB64 {
				out.BodyB64 = base64.StdEncoding.EncodeToString(out.Body)
			}
		}
		rec.Resp = out
		return rec
	}

	host := domain
	if !strings.Contains(host, ":") {
		host = host + ":80"
	}

	var conn net.Conn
	var err error
	var reader *bufio.Reader
	if proxyURL != nil && proxyURL.Scheme == "http" {
		proxyHost := proxyURL.Host
		if !strings.Contains(proxyHost, ":") {
			proxyHost = proxyHost + ":80"
		}
		conn, err = net.DialTimeout("tcp", proxyHost, timeout)
		if err != nil {
			rec.Error = err.Error()
			return rec
		}
		conn.SetDeadline(time.Now().Add(timeout))

		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", host, host, userAgent)
		if _, err := conn.Write([]byte(connectReq)); err != nil {
			conn.Close()
			rec.Error = err.Error()
			return rec
		}

		reader = bufio.NewReader(conn)
		statusLine, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			rec.Error = err.Error()
			return rec
		}
		fields := strings.Fields(statusLine)
		if len(fields) < 2 || fields[1] != "200" {
			for {
				line, err := reader.ReadString('\n')
				if err != nil || line == "\r\n" {
					break
				}
			}
			conn.Close()
			rec.Error = strings.TrimSpace(statusLine)
			return rec
		}
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
	} else {
		d := &net.Dialer{Timeout: timeout}
		conn, err = safeDialAddr(d, host, timeout)
		if err != nil {
			rec.Error = err.Error()
			return rec
		}
		conn.SetDeadline(time.Now().Add(timeout))
	}

	defer conn.Close()

	rawReq := fmt.Sprintf("%s %s %s/%s\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", fr.method, fr.path, fr.proto, fr.version, domain, userAgent)

	if _, err := conn.Write([]byte(rawReq)); err != nil {
		rec.Error = err.Error()
		return rec
	}

	if includeBody {
		var buf bytes.Buffer
		if reader != nil {
			_, err = io.Copy(&buf, reader)
		} else {
			_, err = io.Copy(&buf, conn)
		}
		if err != nil && buf.Len() == 0 {
			rec.Error = err.Error()
			return rec
		}
		out := parseRawHTTPResponse(buf.Bytes(), true, writeBodyB64)
		rec.Resp = out
		return rec
	}

	if reader == nil {
		reader = bufio.NewReader(conn)
	}
	headerBytes, err := readHTTPHeader(reader, 64*1024)
	if err != nil && len(headerBytes) == 0 {
		rec.Error = err.Error()
		return rec
	}
	out := parseRawHTTPResponse(headerBytes, false, writeBodyB64)
	rec.Resp = out
	return rec
}

func buildTargetURL(domain, path string) string {
	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		return strings.TrimSuffix(domain, "/") + path
	}
	return "http://" + strings.TrimSuffix(domain, "/") + path
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func readHTTPHeader(r *bufio.Reader, maxBytes int) ([]byte, error) {
	var out []byte
	for len(out) < maxBytes {
		b, err := r.ReadByte()
		if err != nil {
			return out, err
		}
		out = append(out, b)
		if len(out) >= 4 && bytes.Equal(out[len(out)-4:], []byte("\r\n\r\n")) {
			return out, nil
		}
	}
	return out, fmt.Errorf("header too large")
}

func mustMarshalJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err == nil {
		return sanitizeJSONLLine(b)
	}
	fallback := surveyRecord{
		Domain: "unknown",
		Error:  "json marshal failed: " + err.Error(),
	}
	out, _ := json.Marshal(fallback)
	return sanitizeJSONLLine(out)
}

func parseRawHTTPResponse(raw []byte, includesBody bool, writeBodyB64 bool) *responseJSON {
	headerPart := raw
	var body []byte
	if includesBody {
		if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
			headerPart = raw[:i]
			body = raw[i+4:]
		}
	} else {
		headerPart = bytes.TrimSuffix(headerPart, []byte("\r\n\r\n"))
	}

	lines := strings.Split(string(headerPart), "\r\n")
	if len(lines) == 0 {
		return &responseJSON{}
	}
	statusLine := strings.TrimSpace(lines[0])
	fields := strings.Fields(statusLine)
	out := &responseJSON{}
	if len(fields) >= 1 {
		out.Proto = fields[0]
	}
	if len(fields) >= 2 {
		if sc, err := strconv.Atoi(fields[1]); err == nil {
			out.StatusCode = sc
		}
	}
	if len(fields) >= 3 {
		out.Status = strings.Join(fields[2:], " ")
	}

	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		out.Headers = append(out.Headers, headerKV{
			K: strings.TrimSpace(k),
			V: strings.TrimSpace(v),
		})
	}

	if includesBody && len(body) > 0 {
		out.Body = append(out.Body[:0], body...)
		if writeBodyB64 {
			out.BodyB64 = base64.StdEncoding.EncodeToString(out.Body)
		}
	}
	return out
}

func sanitizeJSONLLine(line []byte) []byte {
	if bytes.IndexByte(line, '\n') == -1 && bytes.IndexByte(line, '\r') == -1 {
		return line
	}
	line = bytes.ReplaceAll(line, []byte("\r"), []byte(`\r`))
	line = bytes.ReplaceAll(line, []byte("\n"), []byte(`\n`))
	return line
}
