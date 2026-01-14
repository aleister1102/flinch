package main

import (
	"fmt"
)

type requestLine struct {
	Method      string //1
	URI         string //2
	Protocol    string //3
	HTTPVersion string //4
}

var reqMap = make(map[string]int)

func inMap(reqLine string) bool {
	if _, ok := reqMap[reqLine]; !ok {
		reqMap[reqLine]++
		return true
	} else {
		return false
	}
}

var removedCount int
var replacedCount int
var donorCount int
var insertedCount int
var digits string = "0123456789"
var charset string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()-_=+"

func main() {
	baselineGET := createRequest("GET", "/", "HTTP", "1.1")
	baselineOPTIONS := createRequest("OPTIONS", "/", "HTTP", "1.1")
	baselineHEAD := createRequest("HEAD", "/", "HTTP", "1.1")
	baselineDELETE := createRequest("DELETE", "/", "HTTP", "1.1")
	baselineTRACE := createRequest("TRACE", "/", "HTTP", "1.1")

	for i := 1; i <= 4; i++ {
		insertCharacter(baselineGET, i)
		insertCharacter(baselineOPTIONS, i)
		insertCharacter(baselineHEAD, i)
		insertCharacter(baselineDELETE, i)
		insertCharacter(baselineTRACE, i)

		if i != 2 {
			removeCharacter(baselineGET, i)
			removeCharacter(baselineOPTIONS, i)
			removeCharacter(baselineHEAD, i)
			removeCharacter(baselineDELETE, i)
			removeCharacter(baselineTRACE, i)

			replaceCharacter(baselineGET, i)
			replaceCharacter(baselineOPTIONS, i)
			replaceCharacter(baselineHEAD, i)
			replaceCharacter(baselineDELETE, i)
			replaceCharacter(baselineTRACE, i)
		}
	}
	fmt.Printf("Removed: %d, Replaced: %d, Inserted: %d, Starting requests: %d, Total: %d", removedCount, replacedCount, insertedCount, donorCount, donorCount+replacedCount+removedCount+insertedCount)
}

func insertCharacter(request requestLine, part int) {
	var target string
	switch part {
	case 1:
		target = request.Method
	case 2:
		target = request.URI
	case 3:
		target = request.Protocol
	case 4:
		target = request.HTTPVersion
	}

	// Insert 'A' at every possible position
	for i := 0; i <= len(target); i++ {
		newVal := target[:i] + "A" + target[i:]
		processMutation(request, part, newVal, "ins", i)
		insertedCount++
	}
}

func removeCharacter(request requestLine, part int) {
	var target string
	switch part {
	case 1:
		target = request.Method
	case 2:
		target = request.URI
	case 3:
		target = request.Protocol
	case 4:
		target = request.HTTPVersion
	}

	if len(target) == 0 {
		return
	}

	if part == 1 {
		fmt.Println(request.Method, request.URI, request.Protocol, request.HTTPVersion, "base_"+request.Method)
	}

	for i := 0; i < len(target); i++ {
		newVal := target[:i] + target[i+1:]
		processMutation(request, part, newVal, "rm", i)
		removedCount++
	}
}

func replaceCharacter(request requestLine, part int) {
	var target string
	switch part {
	case 1:
		target = request.Method
	case 2:
		target = request.URI
	case 3:
		target = request.Protocol
	case 4:
		target = request.HTTPVersion
	}

	chars := charset
	if part == 4 {
		chars = digits
	}

	count := 0
	for i := 0; i < len(target); i++ {
		for _, c := range chars {
			charStr := string(c)
			if string(target[i]) == charStr {
				continue
			}
			newVal := target[:i] + charStr + target[i+1:]
			count++
			processMutation(request, part, newVal, "sw", count)
			replacedCount++
		}
	}
}

func processMutation(req requestLine, part int, newVal string, typePrefix string, index int) {
	var finalString string
	var method, uri, proto, version string
	method, uri, proto, version = req.Method, req.URI, req.Protocol, req.HTTPVersion

	switch part {
	case 1:
		method = newVal
	case 2:
		uri = newVal
	case 3:
		proto = newVal
	case 4:
		version = newVal
	}

	finalString = method + " " + uri + " " + proto + " " + version

	if inMap(finalString) {
		id := fmt.Sprintf("%s%d_%s_%d", typePrefix, part, req.Method, index)
		fmt.Println(method, uri, proto, version, id)
	}
}

func createRequest(method string, url string, proto string, version string) requestLine {
	var req requestLine
	req.Method = method
	req.URI = url
	req.Protocol = proto
	req.HTTPVersion = version
	donorCount++
	return req
}
