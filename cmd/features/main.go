package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/parquet-go/parquet-go"
)

var skipped int = 0
var redirectedCount int = 0
var lenOfHeaders int
var indHeaders = []string{"date", "last-modified", "transfer-encoding", "content-type", "accept-ranges", "connection", "link", "vary", "x-powered-by", "etag", "public", "x-frame-options", "allow", "content-length"}

// var indHeaders = []string{"allow", "content-type", "content-length", "etag", "last-modified", "x-powered-by", "link"}
var foundNmap int = 0

func IsUpper(s string) bool {
	for _, r := range s {
		if !unicode.IsUpper(r) && unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

func IsLower(s string) bool {
	for _, r := range s {
		if !unicode.IsLower(r) && unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if strings.EqualFold(a, e) {
			return true
		}
	}
	return false
}

func IsNumbers(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

func makeIDMap(filename string) map[string]int {
	IDMap := map[string]int{}
	f, err := os.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	json.Unmarshal([]byte(f), &IDMap)
	return IDMap
}

func trimLeftChars(s string, n int) string {
	m := 0
	for i := range s {
		if m >= n {
			return s[i:]
		}
		m++
	}
	return s[:0]
}

func max(numbers map[string]int) int {
	var maxNumber int
	for _, maxNumber = range numbers {
		break
	}
	for _, n := range numbers {
		if n > maxNumber {
			maxNumber = n
		}
	}
	return maxNumber
}

func requestMappings(mapPath string) map[string]string {
	requests := make(map[string]string)
	csvFile, err := os.Open(mapPath)
	if err != nil {
		log.Fatal(err)
	}
	defer csvFile.Close()
	csvReader := csv.NewReader(csvFile)
	csvReader.FieldsPerRecord = -1
	for {
		rec, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		if len(rec) == 0 {
			continue
		}
		var k, v string
		if len(rec) >= 8 {
			k = strings.TrimSpace(rec[6])
			v = strings.TrimSpace(rec[7])
		} else if len(rec) >= 2 {
			k = strings.TrimSpace(rec[0])
			v = strings.TrimSpace(rec[1])
		} else {
			continue
		}
		if k == "" || v == "" {
			continue
		}
		if strings.EqualFold(k, "req_type") && strings.EqualFold(v, "id") {
			continue
		}
		requests[k] = v
	}
	return requests
}

func createCSVwithHeaders(filename string) {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalln("failed to create/open file", err)
	}
	defer f.Close()
	// var csvHeaders []string
	csvHeaders := []string{"url", "request", "str_parent1_request_type", "str_parent2_request_type", "request_type_id", "filtered_headers_id", "status_code_id", "status_message_id", "has_body", "has_st_code", "has_st_msg"}
	sort.Strings(indHeaders)
	for _, header := range indHeaders {
		csvHeaders = append(csvHeaders, header+"_presence_id")
		csvHeaders = append(csvHeaders, header+"_case_id")
		csvHeaders = append(csvHeaders, header+"_field_id")
		csvHeaders = append(csvHeaders, header+"_value_id")
	}
	csvHeaders = append(csvHeaders, "target")
	csvHeaders = append(csvHeaders, "nmap_target")
	fmt.Println(len(csvHeaders))

	lenOfHeaders = len(csvHeaders)
	w := csv.NewWriter(f)
	defer w.Flush()

	w.Write(csvHeaders)
}

func main() {
	inputDir := flag.String("input", "", "path to input directory (responses)")
	outputFile := flag.String("output", "features.csv", "path to output CSV file")
	dataDir := flag.String("data", "data", "path to data directory containing ID maps and csvs")
	flag.Parse()

	if *inputDir == "" {
		fmt.Println("Please provide input directory using -input")
		flag.PrintDefaults()
		os.Exit(1)
	}

	createCSVwithHeaders(*outputFile)
	parseFiles(*inputDir, *outputFile, *dataDir)
	fmt.Println("We skipped this much rows: ", skipped)
	fmt.Println("We skipped this much files because of redirect issues ", redirectedCount)
	fmt.Println("Found in nmap results (urls): ", foundNmap)
}

func parseFiles(path string, pathToCSV string, dataDir string) {
	// fuzzTypes := []string{"ins1_GET", "ins1_OPTIONS", "ins1_HEAD", "ins1_DELETE", "ins1_TRACE", "base_GET", "base_HEAD", "base_OPTIONS", "base_TRACE", "base_DELETE"}
	// fuzzTypes := []string{"ins1_GET", "ins2_GET", "ins3_GET", "ins4_GET", "sw1_GET", "sw2_GET", "sw3_GET", "sw4_GET", "rm1_GET", "rm2_GET", "rm3_GET", "rm4_GET", "ins1_OPTIONS", "ins2_OPTIONS", "ins3_OPTIONS", "ins4_OPTIONS", "sw1_OPTIONS", "sw2_OPTIONS", "sw3_OPTIONS", "sw4_OPTIONS", "rm1_OPTIONS", "rm2_OPTIONS", "rm3_OPTIONS", "rm4_OPTIONS", "ins1_HEAD", "ins2_HEAD", "ins3_HEAD", "ins4_HEAD", "sw1_HEAD", "sw2_HEAD", "sw3_HEAD", "sw4_HEAD", "rm1_HEAD", "rm2_HEAD", "rm3_HEAD", "rm4_HEAD", "ins1_DELETE", "ins2_DELETE", "ins3_DELETE", "ins4_DELETE", "sw1_DELETE", "sw2_DELETE", "sw3_DELETE", "sw4_DELETE", "rm1_DELETE", "rm2_DELETE", "rm3_DELETE", "rm4_DELETE", "ins1_TRACE", "ins2_TRACE", "ins3_TRACE", "ins4_TRACE", "sw1_TRACE", "sw2_TRACE", "sw3_TRACE", "sw4_TRACE", "rm1_TRACE", "rm2_TRACE", "rm3_TRACE", "rm4_TRACE", "base_GET", "base_HEAD", "base_OPTIONS", "base_TRACE", "base_DELETE"}
	filteredHeaders := []string{"Date", "Content-Type", "Content-Length", "Last-Modified", "Connection", "Accept-Ranges", "Transfer-Encoding", "Allow"}
	headerID := makeIDMap(filepath.Join(dataDir, "vm_unique_headers_ids.json"))
	headerKeys := make([]string, 0, len(headerID))
	for k := range headerID {
		headerKeys = append(headerKeys, k)
	}
	sort.Strings(headerKeys)
	// reqTypeID := makeIDMap("reqTypeID.json")
	// reqTypeIDKeys := make([]string, 0, len(reqTypeID))
	// for _, v := range reqTypeID {
	// 	reqTypeIDKeys = append(reqTypeIDKeys, strconv.Itoa(v))
	// }
	// sort.Strings(reqTypeIDKeys)
	typeMap := requestMappings(filepath.Join(dataDir, "map.csv"))
	codeID := makeIDMap(filepath.Join(dataDir, "vm_unique_status_code_ids.json"))
	// fmt.Println(max(codeID))
	// fmt.Println(codeID)
	msgID := makeIDMap(filepath.Join(dataDir, "vm_unique_status_message_ids.json"))
	valueID := makeIDMap(filepath.Join(dataDir, "vm_unique_header_values_ids.json"))
	valueKeys := make([]string, 0, len(headerID))
	for k := range valueID {
		valueKeys = append(valueKeys, k)
	}
	// map[200:10001 400:10006 403:10005 404:10002 405:10007 501:10004 505:10003]

	sort.Strings(valueKeys)
	filteredHeadersID := make(map[string]int)
	// fmt.Println(max(codeID))
	// fmt.Println(max(msgID))
	// fmt.Println(max(valueID))
	// time.Sleep(10 * time.Minute)
	filteredHeadersIDCounter := 10000

	// nmap_results_80_clean_all.csv
	nmapResults := make(map[string]string)
	nmapFile, err := os.Open(filepath.Join(dataDir, "nmap_results_80_clean_all.csv"))

	if err != nil {
		nmapResults = map[string]string{}
	} else {
		defer nmapFile.Close()
		nmapLines, err := csv.NewReader(nmapFile).ReadAll()
		if err != nil {
			log.Fatal(err)
		}
		for _, line := range nmapLines {
			if len(line) < 2 {
				continue
			}
			nmapResults[line[0]] = line[1]
		}
	}

	resFile, err := os.OpenFile(pathToCSV, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer resFile.Close()
	csvWriter := csv.NewWriter(resFile)
	defer csvWriter.Flush()

	filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		var statusCode string
		var statusMessage string
		var headers []string
		var headerValues []string
		var serverValue []string
		// var headersString string
		var filteredFound string
		var serverValue2 []string
		var redirected bool
		var reqLine string
		var nmapValue string
		var hasBody bool
		var hasStatusCode bool
		var hasStatusMessage bool
		fileName := info.Name()
		fileBaseName := strings.TrimSuffix(fileName, filepath.Ext(fileName))

		if _, ok := nmapResults[strings.ToLower(fileBaseName)]; ok {
			foundNmap++
			nmapValue = nmapResults[strings.ToLower(fileBaseName)]

		} else {
			nmapValue = "no_nmap_result"
		}
		records, err := readSurveyRecords(path)
		if err != nil {
			log.Fatal(err)
		}
		if len(records) == 0 {
			skipped++
			return nil
		}

		for _, rec := range records {
			var csvFields []string
			statusCode, statusMessage, headers, serverValue, hasBody, headerValues, reqLine, redirected = stringManipulationJSON(rec)
			if redirected {
				redirectedCount++
				return nil
			}
			if !IsNumbers(statusCode) {
				skipped++
				continue
			}
			serverValue2 = append(serverValue2, serverValue...)

			for i := 0; i < len(headers); i++ {
				if contains(filteredHeaders, headers[i]) {
					if i == 0 {
						filteredFound = filteredFound + headers[i]

					} else {
						filteredFound = filteredFound + " " + headers[i]
					}
				} else {
					continue
				}
			}
			if filteredFound == "" {
				filteredFound = "no_headers"
			}
			if filteredFound[:1] == " " {
				filteredFound = trimLeftChars(filteredFound, 1)
			}
			var server string
			for i := 0; i < len(serverValue2); i++ {
				if serverValue2[i] != "no_server_header_found" {
					server = serverValue2[i]
				} else {
					continue
				}
			}
			if server == "" {
				server = "unknown"
			}
			var reqType string
			var reqTypeID string
			reqLineSlice := strings.Split(reqLine, " ")
			reqType = reqLineSlice[len(reqLineSlice)-1]
			if _, ok := typeMap[reqType]; ok {
				reqTypeID = typeMap[reqType]
			}
			csvFields = append(csvFields, fileBaseName)
			csvFields = append(csvFields, reqLine)
			parentType := strings.Split(reqType, "_")
			csvFields = append(csvFields, parentType[0])
			if len(parentType) <= 1 {
				csvFields = append(csvFields, parentType[0])
			} else {
				csvFields = append(csvFields, parentType[0]+"_"+parentType[1])
			}

			csvFields = append(csvFields, reqTypeID)

			if _, ok := filteredHeadersID[filteredFound]; !ok {
				filteredHeadersID[filteredFound] = filteredHeadersIDCounter
				filteredHeadersIDCounter++
			}

			if _, ok := msgID[statusMessage]; !ok {
				if statusMessage != "no_status_message" {
					next := max(msgID) + 1
					if next < 10001 {
						next = 10001
					}
					msgID[statusMessage] = next
				} else {
					msgID[statusMessage] = 10000
				}
			}

			if _, ok := codeID[statusCode]; !ok {
				if statusMessage != "no_status_message" {
					next := max(codeID) + 1
					if next < 10001 {
						next = 10001
					}
					codeID[statusCode] = next
				} else {
					codeID[statusCode] = 10000
				}
			}

			csvFields = append(csvFields, strconv.Itoa(filteredHeadersID[filteredFound]))
			csvFields = append(csvFields, strconv.Itoa(codeID[statusCode]))
			csvFields = append(csvFields, strconv.Itoa(msgID[statusMessage]))
			if hasBody {
				csvFields = append(csvFields, "1")
			} else {
				csvFields = append(csvFields, "0")
			}
			if statusCode != "no_status_code" && statusCode != "" {
				hasStatusCode = true
			} else {
				hasStatusCode = false
			}
			if statusMessage != "no_status_message" && statusMessage != "" {
				hasStatusMessage = true
			} else {
				hasStatusMessage = false
			}
			if hasStatusCode {
				csvFields = append(csvFields, "1")
			} else {
				csvFields = append(csvFields, "0")
			}
			if hasStatusMessage {
				csvFields = append(csvFields, "1")
			} else {
				csvFields = append(csvFields, "0")
			}
			for _, header := range indHeaders {
				if contains(headers, header) {
					for i := range headers {
						if strings.EqualFold(headers[i], header) {
							if _, ok := valueID[headerValues[i]]; !ok {
								next := max(valueID) + 1
								if next < 10001 {
									next = 10001
								}
								valueID[headerValues[i]] = next
							}
							headerValueID := valueID[headerValues[i]]
							fieldID := strconv.Itoa(headerID[header])
							if fieldID == "" || fieldID == " " {
								fieldID = "10000"
							}
							csvFields = append(csvFields, "1")
							if IsUpper(headers[i]) {
								csvFields = append(csvFields, "10001")
							} else if IsLower(headers[i]) {
								csvFields = append(csvFields, "10002")
							} else {
								csvFields = append(csvFields, "10003")
							}
							csvFields = append(csvFields, fieldID)
							if headerValueID == 0 {
								headerValueID = 10000
							}
							csvFields = append(csvFields, strconv.Itoa(headerValueID))
						}
					}
				} else {
					csvFields = append(csvFields, "0")
					csvFields = append(csvFields, "10000")
					csvFields = append(csvFields, "10000")
					csvFields = append(csvFields, "10000")
				}
			}
			if strings.Contains(server, "/") {
				noVersion := strings.SplitN(server, "/", 2)
				csvFields = append(csvFields, strings.Trim(strings.ToLower(noVersion[0]), " "))
			} else {
				csvFields = append(csvFields, strings.Trim(strings.ToLower(server), " "))
			}
			csvFields = append(csvFields, nmapValue)

			filteredFound = ""
			if len(csvFields) != lenOfHeaders {
				skipped++
				continue
			}
			if contains(csvFields, "<") || contains(csvFields, ">") {
				skipped++
				continue
			}
			if strings.Join(csvFields, "") != "" {
				if err := csvWriter.Write(csvFields); err != nil {
					log.Fatal(err)
				}
			} else {
				skipped++
				continue
			}
		}

		return nil

	})

	fmt.Println("header value map: ", valueID)
	fmt.Println("___________________")
	fmt.Println("st message map: ", msgID)
	fmt.Println("___________________")
	fmt.Println("st code map: ", codeID)
	fmt.Println("___________________")
	fmt.Println("filtered headers map: ", filteredHeadersID)

}

type surveyJSONRecord struct {
	Domain  string `json:"domain"`
	Error   string `json:"error"`
	Request struct {
		Raw string `json:"raw"`
	} `json:"request"`
	Response *struct {
		StatusCode int    `json:"status_code"`
		Status     string `json:"status"`
		Headers    []struct {
			K string `json:"k"`
			V string `json:"v"`
		} `json:"headers"`
		BodyB64 string `json:"body_b64"`
	} `json:"response"`
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

func readSurveyRecords(filePath string) ([]surveyJSONRecord, error) {
	if strings.EqualFold(filepath.Ext(filePath), ".parquet") {
		rows, err := parquet.ReadFile[surveyParquetRow](filePath)
		if err != nil {
			return nil, err
		}
		out := make([]surveyJSONRecord, 0, len(rows))
		for _, row := range rows {
			var rec surveyJSONRecord
			rec.Domain = row.Domain
			rec.Error = row.Error
			rec.Request.Raw = row.RequestRaw

			if row.RespStatusCode != 0 || row.RespStatus != "" || row.RespProto != "" || row.RespHeadersJSON != "" || len(row.RespBody) > 0 {
				rec.Response = &struct {
					StatusCode int    `json:"status_code"`
					Status     string `json:"status"`
					Headers    []struct {
						K string `json:"k"`
						V string `json:"v"`
					} `json:"headers"`
					BodyB64 string `json:"body_b64"`
				}{}
				rec.Response.StatusCode = int(row.RespStatusCode)
				rec.Response.Status = row.RespStatus

				if row.RespHeadersJSON != "" {
					var headers []struct {
						K string `json:"k"`
						V string `json:"v"`
					}
					_ = json.Unmarshal([]byte(row.RespHeadersJSON), &headers)
					rec.Response.Headers = headers
				}
				if len(row.RespBody) > 0 {
					rec.Response.BodyB64 = "1"
				}
			}

			out = append(out, rec)
		}
		return out, nil
	}

	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return parseSurveyJSONL(string(b)), nil
}

func parseSurveyJSONL(contents string) []surveyJSONRecord {
	var out []surveyJSONRecord
	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec surveyJSONRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		out = append(out, rec)
	}
	return out
}

func stringManipulationJSON(rec surveyJSONRecord) (string, string, []string, []string, bool, []string, string, bool) {
	var headers []string
	var serverHeader []string
	var headerValues []string
	hasBody := false
	redirected := false

	reqLine := rec.Request.Raw
	if rec.Response == nil || rec.Error != "" {
		return "no_status_code", "no_status_message", []string{"no_headers"}, []string{"no_server_header_found"}, false, []string{"no_headers"}, reqLine, redirected
	}

	statusCode := strconv.Itoa(rec.Response.StatusCode)
	statusMessage := rec.Response.Status
	if statusMessage == "" {
		statusMessage = "no_status_message"
	}
	if rec.Response.BodyB64 != "" {
		hasBody = true
	}

	for _, h := range rec.Response.Headers {
		headers = append(headers, h.K)
		headerValues = append(headerValues, h.V)
		if strings.EqualFold(h.K, "Server") {
			serverHeader = append(serverHeader, h.V)
		}
	}
	if len(headers) == 0 {
		headers = append(headers, "no_headers")
		headerValues = append(headerValues, "no_headers")
	}
	if len(serverHeader) == 0 {
		serverHeader = append(serverHeader, "no_server_header_found")
	}

	return statusCode, statusMessage, headers, serverHeader, hasBody, headerValues, reqLine, redirected
}
