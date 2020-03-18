package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"
)

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
	APIKey, err := getAPIKey("https://challenger.btbsecurity.com/auth")

	if err != nil {
		//obligated to use variables.
		fmt.Println("Sorry! There was an error: ", err)
	} else {
		fmt.Println("Your API Key", APIKey)
	}

	EntryInfo := getEntryCount(APIKey)
	fmt.Println("EntryCount: ", EntryInfo.EntryCount)
	fmt.Println("LastEntryHash: ", EntryInfo.LastEntryHash)

	LogDataJSON := getLogData(APIKey, 0, 400)

	fmt.Println("EntryCount: ", LogDataJSON[0].ID)

	NewJSONData := cleanData(LogDataJSON)

	fmt.Println("FUN: ", NewJSONData[0].ID)
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
		newEntry.UserName = strings.Replace(strings.ToLower(res[i].UserName), "username is: ", "", -1)
		newEntry.SourceIp = res[i].SourceIp[0]
		newEntry.Target = res[i].Target
		newEntry.Action = res[i].Action
		newEntry.EventTime = time.Unix(int64(res[i].EventTime), 0).Format(time.RFC822Z)
		NewFormat[i] = newEntry

	}

	return NewFormat
}

/*
type DataPulledFromAPI_enum int32

const (
	ID        MessageType = 0
	UserName  MessageType = 1
	SourceIp  MessageType = 2
	Target    MessageType = 3
	Action    MessageType = 4
	EventTime MessageType = 5
)*/

//https://stackoverflow.com/questions/31467326/golang-modify-json-without-struct
//https://stackoverflow.com/questions/23287140/how-do-i-iterate-over-a-json-array-in-golang
