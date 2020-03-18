package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

const LOGFILENAME string = "./resources/Logs.json"
const ENTRYDATAFILENAME string = "./resources/EntryInfo.json"
const APIKEYFILENAME string = "./resources/apikey.txt"

//When no arguments are passed to get-event.
type EntryInformation struct {
	EntryCount    int    `json:"EntryCount"`
	LastEntryHash string `json:"LastEntryHash"`
}

//Data how it is from the API
type DataPulledFromAPI struct {
	ID        int      `json:"id"`
	UserName  string   `json:"user_Name"`
	SourceIp  []string `json:"ips"`
	Target    string   `json:"target"`
	Action    string   `json:"EVENT_0_ACTION"`
	EventTime int      `json:"DateTimeAndStuff"`
}

//Sanitized datas
type NewJSONData struct {
	ID        int    `json:"ID"`
	UserName  string `json:"UserName"`
	SourceIp  string `json:"SourceIp"`
	Target    string `json:"Target"`
	Action    string `json:"Action"`
	EventTime string `json:"EventTime"`
}

func main() {
	ConnectToAPI()

}

func ConnectToAPI() {
	if _, err := os.Stat(APIKEYFILENAME); err != nil {
		if os.IsNotExist(err) {
			ReceivedAPIKey, err := getAPIKey("https://challenger.btbsecurity.com/auth")
			file, err := os.Create(APIKEYFILENAME)
			_, err = io.WriteString(file, ReceivedAPIKey)
			PrintError(err)
		}
	}

	file, err := os.Open(APIKEYFILENAME)
	PrintError(err)
	ReadAll, err := ioutil.ReadAll(file)

	APIKey := string(ReadAll)
	fmt.Println("Your API Key", APIKey)

	CurrentEntryInfo := getEntryCount(APIKey)

	/*

	 "pulls all of the latest entries from the API without getting previous retrieved entries (no duplicates)."

	 The API returns the value "EntryCount".
	 With this, we can discover if new logs were generated.
	 If so, we want to get the latest ones.

	*/
	fmt.Println("Reading entry data file.")

	PreviousEntryInfoIO, err := ioutil.ReadFile(ENTRYDATAFILENAME)
	PrintError(err)

	var preventryinfo EntryInformation
	err = json.Unmarshal(PreviousEntryInfoIO, &preventryinfo)
	var GetLatestLogs bool
	GetLatestLogs = false

	if preventryinfo.EntryCount < CurrentEntryInfo.EntryCount {
		CreateFileIfDoesntExist(ENTRYDATAFILENAME)

		file1, _ := json.MarshalIndent(CurrentEntryInfo, "", " ")
		_ = ioutil.WriteFile(ENTRYDATAFILENAME, file1, 0644)
		GetLatestLogs = true
	}

	if GetLatestLogs {
		const NumberOfEntriesToGetAtATime int = 400

		fmt.Println(fmt.Sprintf("New logs available."))
		fmt.Println(fmt.Sprintf("Old Count: %v   New Count: %v", preventryinfo.EntryCount, CurrentEntryInfo.EntryCount))

		if preventryinfo.EntryCount == 0 {
			preventryinfo.EntryCount = -1
		}

		/*
			I found a bug with the API.
			When you enter an amount in "from" field. Usually, it will make this the lower range.
			However, for values like "5212", it will actually grab the entry "5211"
		*/
		for i := preventryinfo.EntryCount; i < CurrentEntryInfo.EntryCount; i += NumberOfEntriesToGetAtATime {
			fmt.Println(fmt.Sprintf("Reading log id range %v through %v.", i, i+NumberOfEntriesToGetAtATime-1))
			LogDataJSON := getLogData(APIKey, i, i+NumberOfEntriesToGetAtATime-1)
			CleanJSONData := cleanData(LogDataJSON)

			CreateFileIfDoesntExist(LOGFILENAME)

			f, err := os.OpenFile(LOGFILENAME, os.O_APPEND|os.O_WRONLY, 0600)
			PrintError(err)

			defer f.Close()

			result, err := json.Marshal(CleanJSONData)
			PrintError(err)

			var n int
			n, err = f.WriteString(string(result))
			if err != nil {
				fmt.Println(n, err)
			}
		}
	} else {
		fmt.Println("The logs are up-to-date.")
	}
}
func PrintError(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func CreateFileIfDoesntExist(filename string) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		emptyFile, err := os.Create(filename)
		if err != nil {
			log.Fatal(err)
		}
		log.Println(emptyFile)
		emptyFile.Close()
	}
}

//Get API key from website
func getAPIKey(url string) (APIKey string, err error) {
	filename := path.Base(url)
	fmt.Println("Grabbing API key. ", url, " to ", filename)

	resp, err := http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	//convert readcloser to string
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)

	APIKey = buf.String()

	return
}

func getEntryCount(APIKey string) (res EntryInformation) {
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}

	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", "https://challenger.btbsecurity.com/get-events", nil)
	req.Header.Set("Authorization", APIKey)
	respx, err := client.Do(req)

	if err != nil {
		//obligated to use variables.
		fmt.Println("Sorry! There was an error: ", err)
	} else {
		/*
			The API returns byte data

			Un-marshalling is the process
			of converting byte data to JSON
		*/

		buf := new(bytes.Buffer)
		buf.ReadFrom(respx.Body)
		bytes := []byte(buf.Bytes())
		json.Unmarshal(bytes, &res)

		//buf.ReadFrom(respx.Body)
		//fmt.Println("Response as a string: ", buf.String())
	}
	return
}

func getLogData(APIKey string, To int, From int) (res []DataPulledFromAPI) {
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}

	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://challenger.btbsecurity.com/get-events?from=%v&to=%v", To, From), nil)
	req.Header.Set("Authorization", APIKey)
	respx, err := client.Do(req)

	if err != nil {
		fmt.Println("Sorry! There was an error: ", err)
	} else {

		buf := new(bytes.Buffer)
		buf.ReadFrom(respx.Body)
		bytes := []byte(buf.Bytes())

		json.Unmarshal(bytes, &res)

		//buf.ReadFrom(respx.Body)
		//fmt.Println("Response as a string: ", buf.String())
	}
	return
}

func cleanData(res []DataPulledFromAPI) []NewJSONData {

	/*
		Golang would allow me to initilize an array with a nonconstant value
		So I had to "create a slice with make"
		https://tour.golang.org/moretypes/13
	*/
	var NewFormat = make([]NewJSONData, len(res))

	for i := range res {
		var newEntry NewJSONData
		newEntry.ID = res[i].ID
		newEntry.UserName = strings.Replace(strings.ToLower(res[i].UserName), "username is: ", "", -1)
		newEntry.SourceIp = res[i].SourceIp[0]
		newEntry.Target = res[i].Target
		newEntry.Action = res[i].Action
		newEntry.EventTime = time.Unix(int64(res[i].EventTime), 0).Format(time.RFC822Z)
		NewFormat[i] = newEntry

	}

	return NewFormat
}

//https://stackoverflow.com/questions/31467326/golang-modify-json-without-struct
//https://stackoverflow.com/questions/23287140/how-do-i-iterate-over-a-json-array-in-golang
