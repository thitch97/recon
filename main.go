package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
)

func main() {

	var config struct {
		Endpoint string
		File     string
		ApiKey   string
	}

	var err error

	flag.StringVar(&config.Endpoint, "endpoint", "https://www.virustotal.com/api/v3", "VirusTotal Endpoint")
	flag.StringVar(&config.File, "file", "", "Path to file to upload")
	flag.Parse()

	if config.Endpoint == "" {
		fail(errors.New("missing required input \"endpoint\""))
		// panic(err)
	}

	if config.File == "" {
		fail(errors.New("missing required input \"file\""))
		// panic(err)
	}

	fmt.Println("======= VET REPORT =======")

	config.ApiKey = os.Getenv("VIRUSTOTAL_API_KEY")

	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	fileWriter, err := bodyWriter.CreateFormFile("file", config.File)
	if err != nil {
		fmt.Println("error writing to buffer")
		panic(err)
	}

	file, err := os.Open(config.File)
	if err != nil {
		fmt.Println("error opening file")
		panic(err)
	}
	defer file.Close()

	_, err = io.Copy(fileWriter, file)
	if err != nil {
		panic(err)
	}

	bodyWriter.Close()

	uploadReq, _ := http.NewRequest("POST", fmt.Sprintf("%s/files", config.Endpoint), bodyBuf)

	uploadReq.Header.Set("Content-Type", bodyWriter.FormDataContentType())

	uploadReq.Header.Set("x-apikey", config.ApiKey)

	resp, err := http.DefaultClient.Do(uploadReq)
	if err != nil {
		panic(err)
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("%d\n", resp.StatusCode)
	}

	defer resp.Body.Close()

	var uploadRespObj struct {
		Data struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"data"`
	}

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&uploadRespObj)
	if err != nil {
		panic(err)
	}

	analysisReq, err := http.NewRequest("GET", fmt.Sprintf("%s/analyses/%s", config.Endpoint, uploadRespObj.Data.ID), nil)
	if err != nil {
		panic(err)
	}

	analysisReq.Header.Set("x-apikey", config.ApiKey)

	analysisResp, err := http.DefaultClient.Do(analysisReq)
	if err != nil {
		panic(err)
	}

	if analysisResp.StatusCode != http.StatusOK {
		fmt.Printf("%d\n", analysisResp.StatusCode)
	}

	defer analysisResp.Body.Close()

	var analysisRespObj struct {
		Data struct {
			Attributes struct {
				Stats struct {
					Failure    int `json:"failure"`
					Harmless   int `json:"harmless"`
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Timeout    int `json:"timeout"`
					Undetected int `json:"undetected"`
				} `json:"stats"`
				Status string `json:"status"`
			} `json:"attributes"`
		} `json:"data"`
		Meta struct {
			FileInfo struct {
				SHA256 string `json:"sha256"`
				Name   string `json:"name"`
			} `json:"file_info"`
		} `json:"meta"`
	}

	analysisDecoder := json.NewDecoder(analysisResp.Body)
	err = analysisDecoder.Decode(&analysisRespObj)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Analysis ID: %s\n", uploadRespObj.Data.ID)
	fmt.Printf("Status: %s\n", analysisRespObj.Data.Attributes.Status)
	fmt.Println()

	fmt.Println("====== File Info ======")
	fmt.Printf("Name: %s\n", analysisRespObj.Meta.FileInfo.Name)
	fmt.Printf("SHA256: %s\n", analysisRespObj.Meta.FileInfo.SHA256)
	fmt.Println()

	fmt.Println("====== Statistics ======")
	fmt.Printf("Failure: %d\n", analysisRespObj.Data.Attributes.Stats.Failure)
	fmt.Printf("Harmless: %d\n", analysisRespObj.Data.Attributes.Stats.Harmless)
	fmt.Printf("Malicious: %d\n", analysisRespObj.Data.Attributes.Stats.Malicious)
	fmt.Printf("Suspicious: %d\n", analysisRespObj.Data.Attributes.Stats.Suspicious)
	fmt.Printf("Timeout: %d\n", analysisRespObj.Data.Attributes.Stats.Timeout)
	fmt.Printf("Undetected: %d\n", analysisRespObj.Data.Attributes.Stats.Undetected)
	fmt.Println()

}

func fail(err error) {
	fmt.Printf("Error: %s", err)
	os.Exit(1)
}
