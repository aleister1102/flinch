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
	for {
		rec, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		requests[rec[6]] = rec[7]
	}
	// 6 and 7 elements of line array
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
		log.Fatal(err)
	}
	defer nmapFile.Close()
	nmapLines, err := csv.NewReader(nmapFile).ReadAll()

	if err != nil {
		log.Fatal(err)
	}

	for _, line := range nmapLines {
		nmapResults[line[0]] = line[1]
	}

	filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		fileInfo, err2 := os.Stat(path)
		if err2 != nil {
			log.Fatal(err2)
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
		fileName := filepath.Base(path)

		if _, ok := nmapResults[strings.ToLower(fileName)]; ok {
			foundNmap++
			nmapValue = nmapResults[strings.ToLower(fileName)]

		} else {
			nmapValue = "no_nmap_result"
			// return nil //comment if don't wanna skip files for some reason for vms
		}
		if !fileInfo.IsDir() || fileInfo == nil {
			f, err := os.ReadFile(path)
			if err != nil {
				log.Fatal(err)
			}
			fileString := string(f)
			rawResponse := strings.Split(fileString, "\n______________\n")
			if len(rawResponse) > 1 {
				rawResponse = rawResponse[:len(rawResponse)-2]
			} else {
				rawResponse = strings.Split(fileString, "\n______________\r\n")
			}
			for _, response := range rawResponse {
				var csvFields []string
				if response != "" && response != "unidentified error" {
					statusCode, statusMessage, headers, serverValue, hasBody, headerValues, reqLine, redirected = stringManipulation(response)
					if redirected {
						redirectedCount++
						return nil //uncomment if wild set, comment for vm
					}
					if !IsNumbers(statusCode) {
						skipped++
						continue //comment for vm
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
					// for i := 0; i < len(fuzzTypes); i++ {
					// 	if contains(strings.Split(reqLine, " "), fuzzTypes[i]) {
					// 		reqType = fuzzTypes[i]
					// 		switch {
					// 		case reqType == "base_GET":
					// 			reqTypeID = "10000"
					// 		case reqType == "base_HEAD":
					// 			reqTypeID = "10001"
					// 		case reqType == "base_OPTIONS":
					// 			reqTypeID = "10002"
					// 		case reqType == "base_DELETE":
					// 			reqTypeID = "10003"
					// 		case reqType == "base_TRACE":
					// 			reqTypeID = "10004"
					// 		case reqType == "ins1_GET":
					// 			reqTypeID = "10005"
					// 		case reqType == "ins1_TRACE":
					// 			reqTypeID = "10006"
					// 		case reqType == "ins1_OPTIONS":
					// 			reqTypeID = "10007"
					// 		case reqType == "ins1_HEAD":
					// 			reqTypeID = "10008"
					// 		case reqType == "ins1_DELETE":
					// 			reqTypeID = "10009"
					// 		}
					// 		break
					// 	}
					// }
					csvFields = append(csvFields, fileName)
					csvFields = append(csvFields, reqLine)
					parentType := strings.Split(reqType, "_")
					//par1
					csvFields = append(csvFields, parentType[0])
					//par2
					if len(parentType) <= 1 {
						csvFields = append(csvFields, parentType[0])
					} else {
						csvFields = append(csvFields, parentType[0]+"_"+parentType[1])
					}

					csvFields = append(csvFields, reqTypeID)
					// if codeID[statusCode] == 0 {
					// 	codeID[statusCode] = 10000
					// }

					// if msgID[statusMessage] == 0 {
					// 	msgID[statusMessage] = 10000
					// }

					if _, ok := filteredHeadersID[filteredFound]; !ok {
						filteredHeadersID[filteredFound] = filteredHeadersIDCounter
						filteredHeadersIDCounter++
					}

					if _, ok := msgID[statusMessage]; !ok {
						if statusMessage != "no_status_message" {
							msgID[statusMessage] = max(msgID) + 1
						} else {
							msgID[statusMessage] = 10000
						}

						// fmt.Println(max(msgID))

					}
					// fmt.Println(statusCode)

					if _, ok := codeID[statusCode]; !ok {
						if statusMessage != "no_status_message" {
							codeID[statusCode] = max(codeID) + 1
						} else {
							codeID[statusCode] = 10000
						}
						// fmt.Println(max(codeID))
						// fmt.Println(statusCode)

					}
					//handle st msg and st code IDs not present in VMs

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
									headerValueID := valueID[headerValues[i]]
									//handle headerValues not present in the set
									if _, ok := valueID[headerValues[i]]; !ok {
										valueID[headerValues[i]] = max(valueID) + 1
									}
									fieldID := strconv.Itoa(headerID[header])
									if fieldID == "" || fieldID == " " {
										fieldID = "10000"
									}
									//???
									csvFields = append(csvFields, "1")
									if IsUpper(headers[i]) {
										// csvFields = append(csvFields, "upper") //upper
										csvFields = append(csvFields, "10001")
									} else if IsLower(headers[i]) {
										// csvFields = append(csvFields, "lower") //lower
										csvFields = append(csvFields, "10002")
									} else {
										// csvFields = append(csvFields, "mixed") //mixed
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
				}
				filteredFound = ""
				resFile, err := os.OpenFile(pathToCSV, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
				if err != nil {
					log.Fatalln("failed to open file", err)
				}
				defer resFile.Close()
				w := csv.NewWriter(resFile)
				if len(csvFields) != lenOfHeaders {
					skipped++
					continue // comment for vm
				}
				if contains(csvFields, "<") || contains(csvFields, ">") {
					skipped++
					continue //comment for vm
				}
				if strings.Join(csvFields, "") != "" {
					w.Write(csvFields)
					w.Flush()

				} else {
					skipped++
					continue // comment for vm
				}
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

func stringManipulation(fileContents string) (string, string, []string, []string, bool, []string, string, bool) {
	var headers []string
	var headersWithValue []string
	var serverHeader []string
	var fullResp []string
	var redirected bool
	var hasBody bool
	var headerValues []string
	var reqLine string

	temp := strings.Split(fileContents, "\r\n\r")
	// fmt.Println(temp[len(temp)-2]) // THIS IS THE LAST RESPONSE PART BEFORE THE BODY FOR REDIRECTS
	// fmt.Println(temp[len(temp)-1]) // THIS IS THE BODY
	// temp[0] is a response with no body

	//everything else in temp should either be empty, or body
	// fmt.Println(temp[0])
	if len(temp) > 2 {

		fullResp = strings.Split(temp[len(temp)-2], "\r\n")
		fullResp[0] = trimLeftChars(fullResp[0], 1)
		if !contains(fullResp, "curl") || !contains(fullResp, "echo") {
			reqLine = strings.Split(temp[0], "\ncool_delimiter_333\n")[0]
			// fmt.Println(reqLine)
		}
		redirected = true
		hasBody = true
	} else {
		fullResp = strings.Split(temp[0], "\ncool_delimiter_333\n")
		redirected = false
		hasBody = false
		if len(temp) == 2 {
			hasBody = true
			// fmt.Println(hasBody, temp[len(temp)-1])
		}
		reqLine = strings.Split(temp[0], "\ncool_delimiter_333\n")[0]
	}
	// fmt.Println(fullResp)
	if len(fullResp) >= 2 {

		if !redirected {
			if len(fullResp[1]) != 0 && len(fullResp[1]) >= 4 && fullResp[1][:4] == "HTTP" {
				spaceSplit := strings.Split(fullResp[1], " ")
				// print(spaceSplit)
				statusCode := spaceSplit[1]
				lineSplit := strings.Split(fullResp[1], "\r\n") //can also use this for headers
				// statusMessage := strings.Split(lineSplit[0], " ")
				firstLineLength := len(strings.Split(lineSplit[0], " "))
				i := 2
				var finalStatusMessage string
				for i < firstLineLength {
					if i == 2 {
						finalStatusMessage = finalStatusMessage + (strings.Split(lineSplit[0], " "))[i]
						i++
					} else {
						finalStatusMessage = finalStatusMessage + " " + (strings.Split(lineSplit[0], " "))[i]
						i++
					}
				}

				finalStatusMessage = strings.Trim(finalStatusMessage, "\r")
				//just for testing purposes don't use this
				// msgesList := []string{"METHOD_NOT_ALLOWED", "Page Not Found", "Http to Https", "unknown status", "Method not implemented", "Origin Error", "Origin Connection Time-out", "OK", "Created", "Accepted", "Non-Authoritative Information", "No Content", "Reset Content",
				// 	"Partial Content", "Multi-Status", "Already Reported", "IM Used", "Multiple Choices", "Moved Permanently",
				// 	"Found", "See Other", "Not Modified", "Use Proxy", "Switch Proxy", "Temporary Redirect", "Permanent Redirect",
				// 	"Bad Request", "Unauthorized", "Payment Required", "Forbidden", "Not Found", "Method Not Allowed", "Not Acceptable",
				// 	"Proxy Authentication Required", "Request Timeout", "Conflict", "Gone", "Length Required", "Precondition Failed",
				// 	"Payload Too Large", "URI Too Long", "Unsupported Media Type", "Range Not Satisfiable", "Expectation Failed",
				// 	"I'm a teapot", "Misdirected Request", "Unprocessable Entity", "Locked", "Failed Dependency", "Too Early", "Upgrade Required",
				// 	"Precondition Required", "Too Many Requests", "Request Header Fields Too Large", "Unavailable For Legal Reasons", "Internal Server Error",
				// 	"Not Implemented", "Bad Gateway", "Service Unavailable", "Gateway Timeout", "HTTP Version Not Supported", "Variant Also Negotiates",
				// 	"Insufficient Storage", "Loop Detected", "Not Extended", "Network Authentication Required", "", "Not Allowed", "Service Temporarily Unavailable"}
				if len(strings.Split(finalStatusMessage, "\n")) > 1 {
					finalStatusMessage = strings.Split(finalStatusMessage, "\n")[0]
				}

				if finalStatusMessage == "" {
					finalStatusMessage = "no_status_message"
				}
				for n := 1; n < len(lineSplit); n++ {
					header := strings.SplitN(lineSplit[n], ":", 2)
					if len(header) < 2 {
						header = append(header, "no_header")
					}
					headersWithValue = append(headersWithValue, header[0]+":"+header[1])
					headers = append(headers, header[0])
					headerValues = append(headerValues, header[1])
					if strings.EqualFold(header[0], "Server") {
						serverHeader = append(serverHeader, trimLeftChars(header[1], 1))
					}
				}
				return statusCode, finalStatusMessage, headers, serverHeader, hasBody, headerValues, reqLine, redirected
				// return statusCode, finalStatusMessage, headers, serverHeader, hasBody, headersWithValue
			}
		} else {
			if len(fullResp[0]) >= 4 {
				if fullResp[0][:4] == "HTTP" {
					spaceSplit := strings.Split(fullResp[0], " ")
					// print(spaceSplit)
					statusCode := spaceSplit[1]
					lineSplit := strings.Split(fullResp[0], "\r\n") //can also use this for headers
					// statusMessage := strings.Split(lineSplit[0], " ")
					firstLineLength := len(strings.Split(lineSplit[0], " "))
					i := 2
					var finalStatusMessage string
					for i < firstLineLength {
						if i == 2 {
							finalStatusMessage = finalStatusMessage + (strings.Split(lineSplit[0], " "))[i]
							i++
						} else {
							finalStatusMessage = finalStatusMessage + " " + (strings.Split(lineSplit[0], " "))[i]
							i++
						}
					}
					finalStatusMessage = strings.Trim(finalStatusMessage, "\r")
					if finalStatusMessage == "" {
						finalStatusMessage = "no_status_message"
					}
					for n := 1; n < len(lineSplit); n++ {
						header := strings.SplitN(lineSplit[n], ":", 2)
						headersWithValue = append(headersWithValue, header[0]+":"+header[1])
						headers = append(headers, header[0])
						if header[1] != "\n" {
							headerValues = append(headerValues, header[1])
						} else {
							headerValues = append(headerValues, "no_headers")
						}

						if strings.EqualFold(header[0], "Server") {
							serverHeader = append(serverHeader, trimLeftChars(header[1], 1))
						}
					}
					return statusCode, finalStatusMessage, headers, serverHeader, hasBody, headerValues, reqLine, redirected
					// return statusCode, finalStatusMessage, headers, serverHeader, hasBody, headersWithValue

				}
			}
		}

	} else {
		headers = append(headers, "no_headers")
		headerValues = append(headerValues, "no_headers")
		// headersWithValue = append(headersWithValue, "no_headers")
		serverHeader = append(serverHeader, "no_server_header_found")
		return "no_status_code", "no_status_message", headers, serverHeader, hasBody, headerValues, reqLine, redirected
		// return "no_status_code", "no_status_message", headers, serverHeader, hasBody, headersWithValue
	}

	// time.Sleep(10 * time.Second)
	headers = append(headers, "no_headers")
	headerValues = append(headerValues, "no_headers")

	// headersWithValue = append(headersWithValue, "no_headers")
	serverHeader = append(serverHeader, "no_server_header_found")

	return "no_status_code", "no_status_message", headers, serverHeader, hasBody, headerValues, reqLine, redirected
	// return "no_status_code", "no_status_message", headers, serverHeader, hasBody, headersWithValue
}
