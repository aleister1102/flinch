package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cheggaaa/pb"
)

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

func getRandomTimeout() time.Duration {
	rand.Seed(time.Now().UnixNano())
	min := 250
	max := 350
	a := time.Duration(rand.Intn(max-min+1) + min)
	return a
}

var fuzzyReqs []string
var wg sync.WaitGroup
var userAgent = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0"
var connClose = " -H \"Connection: close\""

func sleep(ms time.Duration) {
	time.Sleep(time.Millisecond * ms)
}

const MAX = 512 // 1024 crashes on ubuntu (bad file descriptor or too many open files)

func main() {

	csvParam := flag.String("file", "", "path to file")
	columnFlag := flag.String("col", "", "1-based column number containing domains")
	outputDir := flag.String("out", "responses", "output directory for response files")
	requestsFlag := flag.String("requests", "data/request_set.txt", "path to request set file")
	flag.Parse()

	if *csvParam == "" || *columnFlag == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	// ensure output directory exists
	if _, err := os.Stat(*outputDir); os.IsNotExist(err) {
		if mkErr := os.MkdirAll(*outputDir, 0o755); mkErr != nil {
			log.Fatalf("failed to create output dir %s: %v", *outputDir, mkErr)
		}
	}

	domainList := parseCsv(*csvParam, *columnFlag)
	count := len(domainList)
	bar := pb.StartNew(count)
	fuzzFile, err := os.ReadFile(*requestsFlag)
	if err != nil {
		log.Fatal(err)
	}
	fuzzString := string(fuzzFile)
	fuzzArray := strings.Split(fuzzString, "\n")
	for _, line := range fuzzArray {
		if line != "" {
			fuzzyReqs = append(fuzzyReqs, line)
		}
	}
	sem := make(chan int, MAX)
	for _, URL := range domainList[0:] {
		wg.Add(1)
		// go methods(url)
		go func(URL string) {
			sem <- 1
			bar.Increment()
			var retSlice []string
			for _, line := range fuzzyReqs {
				retSlice = append(retSlice, fuzzyRequests(URL, line))
				a := getRandomTimeout()
				sleep(a)
			}
			file, err := os.OpenFile(*outputDir+"/"+URL, os.O_CREATE|os.O_WRONLY, 0o644)

			if err != nil {
				fmt.Println(err)
			}
			writer := bufio.NewWriter(file)
			for _, line := range retSlice {
				_, err := writer.WriteString(line + "\n______________\n")
				if err != nil {
					fmt.Println(err.Error())
				}
			}
			writer.Flush()
			file.Close()
			wg.Done()
			<-sem
		}(URL)

		sleep(500)
	}
	wg.Wait()
}

// func methods(URL string) []string {
// 	var retSlice []string
// 	for _, line := range fuzzyReqs {
// 		retSlice = append(retSlice, fuzzyRequests(URL, line))
// 		a := getRandomTimeout()
// 		// fmt.Println(a)
// 		sleep(a)
// 	}
// 	file, err := os.OpenFile("responses/"+URL, os.O_CREATE|os.O_WRONLY, 0777)

// 	if err != nil {
// 		fmt.Println(err)
// 	}

// 	writer := bufio.NewWriter(file)
// 	for _, line := range retSlice {
// 		_, err := writer.WriteString(line + "\n______________\n")
// 		if err != nil {
// 			fmt.Println(err.Error())
// 		}
// 	}
// 	writer.Flush()
// 	file.Close()

// 	wg.Done()
// 	return retSlice
// }

func parseCsv(filename string, column string) []string {
	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}

	var domainList []string
	csvReader := csv.NewReader(f)
	for {
		rec, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		columnNumbertoInt, _ := strconv.Atoi(column)
		domainList = append(domainList, rec[columnNumbertoInt-1])
	}
	f.Close()
	return domainList
}

func fuzzyRequests(URL string, requestLine string) string {
	spaceSplit := strings.Split(requestLine, " ")
	if len(spaceSplit) == 5 {
		if spaceSplit[2] == "HTTP" && spaceSplit[3] == "1.1" { //curl
			cmd := "curl -L " + "-i " + URL + spaceSplit[1] + " -X " + spaceSplit[0] + " -A " + "\"" + userAgent + "\"" + connClose
			output, err := exec.Command("bash", "-c", cmd).Output()
			if err != nil {
				return err.Error() + " command was " + cmd + " " + spaceSplit[4]
			}
			return (cmd + " " + spaceSplit[4] + "\n" + "cool_delimiter_333" + "\n" + string(output))

		} else { //nc
			cmd := "echo -e \"" + spaceSplit[0] + " " + spaceSplit[1] + " " + spaceSplit[2] + "/" + spaceSplit[3] + "\\r\\nHost: " + URL + "\\r\\nUser-Agent: " + userAgent + "\\r\\n\" | nc -w 10 " + URL + " 80"
			output, err := exec.Command("bash", "-c", cmd).Output()
			if err != nil {
				return err.Error() + " command was " + cmd + " " + spaceSplit[4]
			}
			return (cmd + " " + spaceSplit[4] + "\n" + "cool_delimiter_333" + "\n" + string(output))
		}
	}
	return "unidentified error"
}
