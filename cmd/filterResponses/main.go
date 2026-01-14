package main

import (
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
			rawResponse := strings.Split(fileString, "\n______________\n")
			if len(rawResponse) > 1 {
				rawResponse = rawResponse[:len(rawResponse)-2]
			} else {
				rawResponse = strings.Split(fileString, "\n______________\r\n")
			}
			counter := 0
			for _, response := range rawResponse {
				if strings.HasPrefix(response, "exit") {
					counter++
				}
			}
			if len(rawResponse) == counter {
				fmt.Println(fileName)
			}
		}
		return nil
	})
}
