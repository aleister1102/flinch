package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/parquet-go/parquet-go"
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
	filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		fileName := filepath.Base(filePath)
		if strings.EqualFold(filepath.Ext(fileName), ".parquet") {
			rows, err := parquet.ReadFile[surveyParquetRow](filePath)
			if err != nil {
				log.Printf("read %s: %v", fileName, err)
				return nil
			}
			total := len(rows)
			success := 0
			for _, r := range rows {
				if r.Error == "" && r.RespStatusCode > 0 {
					success++
				}
			}
			if total == 0 || success == 0 {
				if err := os.Remove(filePath); err != nil {
					log.Printf("remove %s: %v", fileName, err)
				} else {
					fmt.Println(fileName)
				}
			}
			return nil
		}

		b, err := os.ReadFile(filePath)
		if err != nil {
			log.Printf("read %s: %v", fileName, err)
			return nil
		}

		fileString := string(b)
		trimmed := strings.TrimSpace(fileString)
		if trimmed == "" || trimmed[0] != '{' {
			if err := os.Remove(filePath); err != nil {
				log.Printf("remove %s: %v", fileName, err)
			} else {
				fmt.Println(fileName)
			}
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
			if err := os.Remove(filePath); err != nil {
				log.Printf("remove %s: %v", fileName, err)
			} else {
				fmt.Println(fileName)
			}
		}
		return nil
	})
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
