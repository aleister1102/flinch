package main

import (
	"bufio"
	"bytes"
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
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
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
}

type surveyRecord struct {
	Domain  string        `json:"domain"`
	Request requestJSON   `json:"request"`
	HTTP11  bool          `json:"http11"`
	Error   string        `json:"error,omitempty"`
	Resp    *responseJSON `json:"response,omitempty"`
}

func main() {
	csvParam := flag.String("f", "", "path to CSV file containing domains")
	columnFlag := flag.String("C", "1", "1-based column number containing domains")
	outputDir := flag.String("o", "responses", "output directory for response files")
	requestsFlag := flag.String("r", "data/request_set.txt", "path to request set file")
	concurrency := flag.Int("c", 100, "maximum number of concurrent domains to process")
	perDomainWorkers := flag.Int("w", 10, "concurrent requests per domain")
	timeout := flag.Duration("t", 10*time.Second, "timeout for each request")
	proxyFlag := flag.String("p", "", "proxy URL (e.g., http://127.0.0.1:8080)")
	includeBody := flag.Bool("B", false, "include response body in output (slower)")
	flag.Parse()

	if strings.TrimSpace(*csvParam) == "" {
		if _, err := os.Stat("data/targets.csv.resolved.csv"); err == nil {
			*csvParam = "data/targets.csv.resolved.csv"
		} else {
			*csvParam = "data/targets.csv"
		}
	}

	colIdx, err := strconv.Atoi(*columnFlag)
	if err != nil || colIdx < 1 {
		log.Fatalf("invalid column number: %s", *columnFlag)
	}
	colIdx-- // 1-based to 0-based

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		log.Fatalf("failed to create output dir %s: %v", *outputDir, err)
	}

	domainList, err := parseCsv(*csvParam, colIdx)
	if err != nil {
		log.Fatalf("failed to parse CSV: %v", err)
	}

	fuzzLines, err := readFuzzFile(*requestsFlag)
	if err != nil {
		log.Fatalf("failed to read fuzz file: %v", err)
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
		fastClient.Dial = fasthttpproxy.FasthttpHTTPDialerTimeout(proxyURL.String(), *timeout)
		fastClient.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}

	for _, domain := range domainList {
		wg.Add(1)
		sem <- struct{}{}
		go func(d string) {
			defer wg.Done()
			defer func() { <-sem }()

			processDomain(d, fuzzLines, *outputDir, fastClient, proxyURL, *timeout, *perDomainWorkers, *includeBody, bar)
		}(domain)
	}

	wg.Wait()
	bar.Finish()
}

func parseCsv(filename string, colIdx int) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var domains []string
	reader := csv.NewReader(f)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if colIdx < len(record) {
			domains = append(domains, record[colIdx])
		}
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

func processDomain(domain string, fuzzLines []fuzzRequest, outputDir string, client *fasthttp.Client, proxyURL *url.URL, timeout time.Duration, workers int, includeBody bool, bar *pb.ProgressBar) {
	// Sanitize domain name for filename
	safeName := strings.ReplaceAll(domain, "/", "_")
	safeName = strings.ReplaceAll(safeName, ":", "_")
	outputPath := filepath.Join(outputDir, safeName)

	file, err := os.Create(outputPath)
	if err != nil {
		log.Printf("error creating file for %s: %v", domain, err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	if workers < 1 {
		workers = 1
	}

	tasks := make(chan fuzzRequest)
	results := make(chan []byte, workers*2)

	var workerWG sync.WaitGroup
	for i := 0; i < workers; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for fr := range tasks {
				results <- executeFuzz(domain, fr, client, proxyURL, timeout, includeBody)
				bar.Increment()
			}
		}()
	}

	go func() {
		for _, fr := range fuzzLines {
			tasks <- fr
		}
		close(tasks)
		workerWG.Wait()
		close(results)
	}()

	for res := range results {
		res = sanitizeJSONLLine(res)
		writer.Write(res)
		writer.WriteByte('\n')
	}
	writer.Flush()
}

func executeFuzz(domain string, fr fuzzRequest, client *fasthttp.Client, proxyURL *url.URL, timeout time.Duration, includeBody bool) []byte {
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
		return mustMarshalJSON(rec)
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
			return mustMarshalJSON(rec)
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
			out.BodyB64 = base64.StdEncoding.EncodeToString(resp.Body())
		}
		rec.Resp = out
		return mustMarshalJSON(rec)
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
			return mustMarshalJSON(rec)
		}
		conn.SetDeadline(time.Now().Add(timeout))

		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", host, host, userAgent)
		if _, err := conn.Write([]byte(connectReq)); err != nil {
			conn.Close()
			rec.Error = err.Error()
			return mustMarshalJSON(rec)
		}

		reader = bufio.NewReader(conn)
		statusLine, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			rec.Error = err.Error()
			return mustMarshalJSON(rec)
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
			return mustMarshalJSON(rec)
		}
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
	} else {
		conn, err = net.DialTimeout("tcp", host, timeout)
		if err != nil {
			rec.Error = err.Error()
			return mustMarshalJSON(rec)
		}
		conn.SetDeadline(time.Now().Add(timeout))
	}

	defer conn.Close()

	rawReq := fmt.Sprintf("%s %s %s/%s\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", fr.method, fr.path, fr.proto, fr.version, domain, userAgent)

	if _, err := conn.Write([]byte(rawReq)); err != nil {
		rec.Error = err.Error()
		return mustMarshalJSON(rec)
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
			return mustMarshalJSON(rec)
		}
		out := parseRawHTTPResponse(buf.Bytes(), true)
		rec.Resp = out
		return mustMarshalJSON(rec)
	}

	if reader == nil {
		reader = bufio.NewReader(conn)
	}
	headerBytes, err := readHTTPHeader(reader, 64*1024)
	if err != nil && len(headerBytes) == 0 {
		rec.Error = err.Error()
		return mustMarshalJSON(rec)
	}
	out := parseRawHTTPResponse(headerBytes, false)
	rec.Resp = out
	return mustMarshalJSON(rec)
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
		return b
	}
	fallback := surveyRecord{
		Domain: "unknown",
		Error:  "json marshal failed: " + err.Error(),
	}
	out, _ := json.Marshal(fallback)
	return out
}

func parseRawHTTPResponse(raw []byte, includesBody bool) *responseJSON {
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
		out.BodyB64 = base64.StdEncoding.EncodeToString(body)
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
