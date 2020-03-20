package main

import (
	"container/list"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"text/template"
	"time"
)

const LOGFILENAME string = "./resources/Logs.json"
const ENTRYDATAFILENAME string = "./resources/EntryInfo.json"

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
	ID        int    `json:"AcmeApiId"`
	UserName  string `json:"UserName"`
	SourceIp  string `json:"SourceIp"`
	Target    string `json:"Target"`
	Action    string `json:"Action"`
	EventTime string  `json:"EventTime"`
}

func main() {
	ConnectToAPI()
	//DisplayPage()
}

//Create a struct that holds information to be displayed in our HTML file
type Welcome struct {
	Name string
}

func DisplayPage() {
	welcome := Welcome{"Anonymous"}

	templates := template.Must(template.ParseFiles("index.html"))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		if err := templates.ExecuteTemplate(w, "index.html", welcome); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	fmt.Println(http.ListenAndServe(":8080", nil))
}

func ConnectToAPI() {
	APIKey, err := getAPIKey("https://challenger.btbsecurity.com/auth")
	PrintError(err)

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
		fmt.Println(fmt.Sprintf("New logs available."))
		fmt.Println(fmt.Sprintf("Old Count: %v   New Count: %v", preventryinfo.EntryCount, CurrentEntryInfo.EntryCount))

		const NumberOfEntriesToGetAtATime int = 499

		for i := preventryinfo.EntryCount; i < CurrentEntryInfo.EntryCount; i += NumberOfEntriesToGetAtATime {
			/*
				This is to offset a bug in the API.
				All from values over 2000 are decreased.
				This code offsets it.
			*/

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

		JSONFix()

		fmt.Println("Checking for duplicate entries")
		input, err := ioutil.ReadFile(LOGFILENAME)
		var jsondata []NewJSONData
		err = json.Unmarshal(input, &jsondata)
		PrintError(err)
		cleanedinput := RemoveDuplicateEntries(jsondata, CurrentEntryInfo.EntryCount)
	
		result, err := json.Marshal(cleanedinput)
	
		err = ioutil.WriteFile(LOGFILENAME, result, 0644)
		PrintError(err)

	} else {
		fmt.Println("The logs are up-to-date.")
	}
}

/*
I'm sure there's a way to prevent this,
but I have to make the JSON entries all be within
a single [].
*/
func JSONFix(){
	input, err := ioutil.ReadFile(LOGFILENAME)
	PrintError(err)
	output := strings.Replace(string(input), "][", ",", -1)
	err = ioutil.WriteFile(LOGFILENAME, []byte(output), 0644)
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

	fmt.Println(fmt.Sprintf("https://challenger.btbsecurity.com/get-events?from=%v&to=%v", To, From))
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
		newEntry.Target = strings.Replace(res[i].Target, "/auth", "", -1)
		newEntry.Action = strings.Replace(strings.Replace(res[i].Action, "Idk", "", -1), "success", "Login Success", -1)
		newEntry.Action = strings.Replace(newEntry.Action, "success", "Login Success", -1)
		newEntry.Action = strings.Replace(newEntry.Action, "Logon Very Success", "Login Success", -1) 
		newEntry.Action = strings.Replace(newEntry.Action, "Success login", "Login Success", -1)
		newEntry.Action = strings.Replace(newEntry.Action, "Failed login", "Login Failure", -1)
		newEntry.Action = strings.Replace(newEntry.Action, "Login failed", "Login Failure", -1)

		loc, _ := time.LoadLocation("UTC")
		newEntry.EventTime = time.Unix(int64(res[i].EventTime), 0).In(loc).Format("2006-01-02 15:04:05 UTC")
		NewFormat[i] = newEntry
	}

	return NewFormat
}

func RemoveDuplicateEntries(res []NewJSONData, maxID int) []NewJSONData {
	var AlreadyContainsID = make([]bool, maxID)

	ListNewLogEntries := list.New()

	var uniqueEntries int
	for i := 0; i < len(res); i++ {
		Id := res[i].ID

		if (AlreadyContainsID[Id] == false){
			AlreadyContainsID[Id] = true
			ListNewLogEntries.PushBack(res[i])
			uniqueEntries++
			//fmt.Println("ID found: ", i)
		} else {
			/*
			2000 in the API was duplicate, however,
			the names are different. 
			I will just remove entries that have 
			duplicate IDs for now.
			*/
			fmt.Println("Duplicate ID found: ", i)
		}
	}

	NewLogEntries := make([]NewJSONData, uniqueEntries)

	var i int
	for e := ListNewLogEntries.Front(); e != nil; e = e.Next() {

		if value, ok := e.Value.(NewJSONData); ok {
			NewLogEntries[i]=value
		} else {
			fmt.Println("Error with casting! Id number: ", i)
		}
		i++
	}

	return NewLogEntries
}
