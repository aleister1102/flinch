package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	dirPtr := flag.String("dir", "", "path to directory containing responses")
	flag.Parse()

	if *dirPtr == "" {
		fmt.Println("Please provide a directory path using -dir flag")
		flag.PrintDefaults()
		os.Exit(1)
	}

	findNonRespondants(*dirPtr)
}

func findNonRespondants(path string) {
	filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		fileInfo, err2 := os.Stat(path)
		if err2 != nil {
			log.Fatal(err2)
		}
		if !fileInfo.IsDir() || fileInfo == nil {
			fileName := filepath.Base(path)
			f, err := os.ReadFile(path)
			if err != nil {
				log.Fatal(err)
			}
			fileString := string(f)
			trimmed := strings.TrimSpace(fileString)
			if trimmed == "" || trimmed[0] != '{' {
				fmt.Println(fileName)
				return nil
			}

			type rec struct {
				Error    string `json:"error"`
				Response *struct {
					StatusCode int `json:"status_code"`
				} `json:"response"`
			}

			total := 0
			success := 0
			for _, line := range strings.Split(fileString, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				total++
				var r rec
				if err := json.Unmarshal([]byte(line), &r); err != nil {
					continue
				}
				if r.Error == "" && r.Response != nil && r.Response.StatusCode > 0 {
					success++
				}
			}

			if total == 0 || success == 0 {
				fmt.Println(fileName)
			}
		}
		return nil
	})
}
