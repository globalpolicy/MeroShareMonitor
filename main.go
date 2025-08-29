package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DPID           string
	BOID           string
	Password       string
	CRN            string
	TransactionPIN string
	DefaultBankID  int
	DefaultKittas  int
	AskForKittas   bool
}

type AvailableIssueObject struct {
	CompanyShareId int
	SubGroup       string
	Scrip          string
	CompanyName    string
	ShareTypeName  string
	ShareGroupName string
	StatusName     string
	IssueOpenDate  string
	IssueCloseDate string
}

type BankBrief struct {
	Code string
	Id   int
	Name string
}

type ScripToApply struct {
	CompanyShareId string
	KittasToApply  string
	BankIdToApply  int
	CompanyName    string
}

type BankDetail struct {
	AccountBranchId int
	AccountNumber   string
	AccountTypeId   int
	AccountTypeName string
	BranchName      string
	Id              int
}

type OwnDetail struct {
	Address                string
	Boid                   string
	ClientCode             string
	Contact                string
	CreatedApproveDate     string
	CreatedApproveDateStr  string
	CustomerTypeCode       string
	Demat                  string
	DematExpiryDate        string
	Email                  string
	ExpiredDate            string
	ExpiredDateStr         string
	Gender                 string
	Id                     int
	ImagePath              string
	MeroShareEmail         string
	Name                   string
	PanNumber              string
	PasswordChangeDate     string
	PasswordChangedDateStr string
	PasswordExpiryDate     string
	PasswordExpiryDateStr  string
	ProfileName            string
	RenderDashboard        bool
	RenewedDate            string
	RenewedDateStr         string
	Username               string
}

type ApplyScripPayloadJSON struct {
	AccountBranchId int    `json:"accountBranchId"`
	AccountNumber   string `json:"accountNumber"`
	AppliedKitta    string `json:"appliedKitta"`
	AccountTypeId   int    `json:"accountTypeId"`
	BankId          int    `json:"bankId"`
	Boid            string `json:"boid"`
	CompanyShareId  string `json:"companyShareId"`
	CrnNumber       string `json:"crnNumber"`
	CustomerId      int    `json:"customerId"`
	Demat           string `json:"demat"`
	TransactionPIN  string `json:"transactionPIN"`
}

func main() {

	addProfileFlag := flag.Bool("add", false, "Add a new profile")
	flag.Parse()

	showIntroMsg()

	files, err := filepath.Glob("./config*.json")
	if err != nil {
		Panic("Error retrieving config file list!")
	}

	if *addProfileFlag || len(files) == 0 {
		DoWork("config" + GetTimestamp() + ".json")
	} else {
		for _, file := range files {
			Log(fmt.Sprint("Working on ", file))
			DoWork(file)
		}
	}

}

func DoWork(configFileName string) {

	clientIdDict := GetClientIds() //load dpid:clientid dictionary

	key, keyerror := GetKey(configFileName)
	if keyerror != nil {
		_ = os.Remove(configFileName) //since keyerror occurred, we don't have the key for decrypting config, so delete the old config

		makeKeyErr := MakeKey(configFileName)
		if makeKeyErr != nil {
			Panic("Could not create key file!") //we won't proceed without creating a key file
		}
		var getKeyErr error
		key, getKeyErr = GetKey(configFileName)
		if getKeyErr != nil {
			Panic("Could not read key file!") //we won't proceed without a key
		}
	}

	//at this point, we will have either the old key or a newly created one
	var config Config

	configContents, err := os.ReadFile(configFileName)
	if err == nil {
		err = json.Unmarshal(configContents, &config)                             //read the config file into config variable
		config.Password, _ = DecryptAES([]byte(key), config.Password)             //decrypt the saved password
		config.TransactionPIN, _ = DecryptAES([]byte(key), config.TransactionPIN) //decrypt the saved transaction PIN
		config.CRN, _ = DecryptAES([]byte(key), config.CRN)                       //decrypt the saved CRN
	}

	if config.BOID == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("Enter your BOID (last eight digits): ")
		boid, _ := reader.ReadString('\n')
		config.BOID = strings.TrimSpace(boid)
	}

	if config.Password == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("Enter your password: ")
		pwd, _ := reader.ReadString('\n')
		config.Password = strings.TrimSpace(pwd)
	}

	if config.TransactionPIN == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("Enter your transaction PIN: ")
		tpin, _ := reader.ReadString('\n')
		config.TransactionPIN = strings.TrimSpace(tpin)
	}

	if config.DPID == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("Enter your Depository Participant ID: ")
		dpid, _ := reader.ReadString('\n')
		config.DPID = strings.TrimSpace(dpid)
	}

	//ask for default number of kittas to apply
	if config.DefaultKittas == 0 {
		fmt.Println("Please enter the default no. of kittas to apply: ")
		reader := bufio.NewReader(os.Stdin)
		kittasStr, _ := reader.ReadString('\n')
		kittas := 0
		fmt.Sscan(strings.TrimSpace(kittasStr), &kittas)
		config.DefaultKittas = kittas
	}

	//login to get the auth token(JWT)
	clientIdStr := clientIdDict[config.DPID]
	clientId := 0
	fmt.Sscan(clientIdStr, &clientId)
	authRequestBody := map[string]interface{}{"clientId": clientId, "username": config.BOID, "password": config.Password}
	req, _ := json.Marshal(authRequestBody)
	resp, err := http.Post("https://webbackend.cdsc.com.np/api/meroShare/auth/", "application/json", bytes.NewBuffer(req))
	if err != nil {
		Panic("Error authenticating!")
	}
	authToken := resp.Header.Get("Authorization")

	//retrieve demat
	request, _ := http.NewRequest("GET", "https://webbackend.cdsc.com.np/api/meroShare/ownDetail/", nil)
	request.Header.Add("Authorization", authToken)
	request.Header.Add("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil || response.StatusCode != 200 {
		Panic("Error getting own details!")
	}
	defer response.Body.Close()
	var ownDetail OwnDetail
	err = json.NewDecoder(response.Body).Decode(&ownDetail)
	if err != nil {
		Panic("Error parsing own details JSON!")
	}
	Log(fmt.Sprint("Obtained auth token for ", ownDetail.Name))

	//ask for default bank and its corresponding CRN to apply from
	if config.DefaultBankID == 0 {
		//load bank brief
		request, _ := http.NewRequest("GET", "https://webbackend.cdsc.com.np/api/meroShare/bank/", bytes.NewBufferString(""))
		request.Header.Add("Authorization", authToken)
		client := &http.Client{}
		response, err := client.Do(request)
		if err != nil {
			Panic("Error getting banks!")
		}
		defer response.Body.Close()

		var bankBriefs []BankBrief
		err = json.NewDecoder(response.Body).Decode(&bankBriefs)
		if err != nil {
			Panic("Error parsing bank briefs JSON!")
		}
		fmt.Println("Please enter the bank ID you'd like to use:")
		for _, bankBrief := range bankBriefs {
			fmt.Println(bankBrief.Name, " ID:", bankBrief.Id)
		}
		reader := bufio.NewReader(os.Stdin)
		bankId, _ := reader.ReadString('\n')
		bankID := 0
		fmt.Sscan(strings.TrimSpace(bankId), &bankID)
		config.DefaultBankID = bankID

		//ask for the bank's CRN
		fmt.Println("Please enter the CRN of this bank: ")
		bankCRN, _ := reader.ReadString('\n')
		config.CRN = strings.TrimSpace(bankCRN)
	}

	//serialize the populated config variable to config file after encrypting them
	encryptedConfig := config //make a copy of config
	encryptedConfig.Password, _ = EncryptAES([]byte(key), config.Password)
	encryptedConfig.TransactionPIN, _ = EncryptAES([]byte(key), config.TransactionPIN)
	encryptedConfig.CRN, _ = EncryptAES([]byte(key), config.CRN)
	serializedData, _ := json.MarshalIndent(encryptedConfig, "", " ")
	_ = os.WriteFile(configFileName, serializedData, 0666)

	//landing here means the config variable and the config file are ready

	//retrieve available issues and create a slice of scrips to apply to
	reqBodyForAvailableIssues := []byte(`{
		"filterFieldParams": [
		  {
			"key": "companyIssue.companyISIN.script",
			"alias": "Scrip"
		  },
		  {
			"key": "companyIssue.companyISIN.company.name",
			"alias": "Company Name"
		  },
		  {
			"key": "companyIssue.assignedToClient.name",
			"value": "",
			"alias": "Issue Manager"
		  }
		],
		"page": 1,
		"size": 10,
		"searchRoleViewConstants": "VIEW_APPLICABLE_SHARE",
		"filterDateParams": [
		  {
			"key": "minIssueOpenDate",
			"condition": "",
			"alias": "",
			"value": ""
		  },
		  {
			"key": "maxIssueCloseDate",
			"condition": "",
			"alias": "",
			"value": ""
		  }
		]
	  }`)
	request, _ = http.NewRequest("POST", "https://webbackend.cdsc.com.np/api/meroShare/companyShare/applicableIssue/", bytes.NewBuffer(reqBodyForAvailableIssues))
	request.Header.Add("Authorization", authToken)
	request.Header.Add("Content-Type", "application/json")
	client = &http.Client{}
	response, err = client.Do(request)
	if err != nil || response.StatusCode != 200 {
		Panic("Error getting applicable issues!")
	}
	defer response.Body.Close()

	var responseJson map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&responseJson)
	if err != nil {
		Panic("Error parsing applicable issues JSON!")
	}

	//damned conversion from []interface{} to []AvailableIssueObject{}
	availableScrips := []AvailableIssueObject{}
	availables := responseJson["object"].([]interface{})
	for _, v := range availables {
		tmp := v.(map[string]interface{})
		if _, isKeyPresent := tmp["action"]; isKeyPresent { //there's an "action" key if this scrip was already applied to
			Log(fmt.Sprint("Skipping recently applied company ", tmp["companyName"].(string)))
			continue
		}
		jsonString, _ := json.Marshal(tmp)
		var availableIssue AvailableIssueObject
		err := json.Unmarshal(jsonString, &availableIssue)
		if err != nil {
			Panic("Error parsing available scrips!")
		}
		availableScrips = append(availableScrips, availableIssue)
	}

	scripsToApply := []ScripToApply{}
	for _, scrip := range availableScrips {
		if !config.AskForKittas {
			if scrip.ShareGroupName == "Ordinary Shares" {
				var scripToApply ScripToApply
				scripToApply.BankIdToApply = config.DefaultBankID
				scripToApply.KittasToApply = strconv.Itoa(config.DefaultKittas)
				scripToApply.CompanyShareId = strconv.Itoa(scrip.CompanyShareId)
				scripToApply.CompanyName = scrip.CompanyName
				scripsToApply = append(scripsToApply, scripToApply)
			}
		} else {
			Log(fmt.Sprint(scrip.CompanyName, "-", scrip.ShareGroupName, "(", scrip.IssueOpenDate, "-", scrip.IssueCloseDate, ")"))
			fmt.Println("Enter the no. of kittas to apply (0 for none): ")
			reader := bufio.NewReader(os.Stdin)
			kittasStr, _ := reader.ReadString('\n')
			kittas := 0
			fmt.Sscan(strings.TrimSpace(kittasStr), &kittas)
			if kittas > 0 {
				var scripToApply ScripToApply
				scripToApply.BankIdToApply = config.DefaultBankID
				scripToApply.KittasToApply = strconv.Itoa(kittas)
				scripToApply.CompanyShareId = strconv.Itoa(scrip.CompanyShareId)
				scripToApply.CompanyName = scrip.CompanyName
				scripsToApply = append(scripsToApply, scripToApply)
			}

		}
	}

	if len(scripsToApply) == 0 {
		Log(fmt.Sprint("No IPOs open right now. Quitting.\n"))
		return
	}

	//retrieve accountNumber and customerId fields (required to apply) from an API call to get the default bank's details
	request, _ = http.NewRequest("GET", "https://webbackend.cdsc.com.np/api/meroShare/bank/"+strconv.Itoa(config.DefaultBankID), nil)
	request.Header.Add("Authorization", authToken)
	request.Header.Add("Content-Type", "application/json")
	client = &http.Client{}
	response, err = client.Do(request)
	if err != nil || response.StatusCode != 200 {
		Panic("Error getting bank details!")
	}
	defer response.Body.Close()

	var bankDetails []BankDetail
	err = json.NewDecoder(response.Body).Decode(&bankDetails)
	if err != nil {
		Panic("Error parsing bank details JSON!")
	}

	//take the first element of the JSON array, which is the required BankDetail JSON object
	bankDetail := bankDetails[0]

	//apply to the companies in scripstoApply slice
	applyReqJson := &ApplyScripPayloadJSON{
		AccountBranchId: bankDetail.AccountBranchId,
		AccountNumber:   bankDetail.AccountNumber,
		AccountTypeId:   bankDetail.AccountTypeId,
		Boid:            ownDetail.Boid,
		CrnNumber:       config.CRN,
		Demat:           ownDetail.Demat,
		CustomerId:      bankDetail.Id,
		TransactionPIN:  config.TransactionPIN,
	}
	for _, scrip := range scripsToApply {
		applyReqJson.AppliedKitta = scrip.KittasToApply
		applyReqJson.BankId = scrip.BankIdToApply
		applyReqJson.CompanyShareId = scrip.CompanyShareId

		reqjson, err := json.Marshal(applyReqJson)
		if err != nil {
			Log("Cannot build apply JSON payload!")
		}
		request, _ = http.NewRequest("POST", "https://webbackend.cdsc.com.np/api/meroShare/applicantForm/share/apply", bytes.NewBuffer(reqjson))
		request.Header.Add("Authorization", authToken)
		request.Header.Add("Content-Type", "application/json")
		client = &http.Client{}
		response, err = client.Do(request)
		if err != nil || response.StatusCode != 201 {
			Log(fmt.Sprint("Error applying to scrip - ", scrip.CompanyName))
		} else {
			Log(fmt.Sprint("Applied ", applyReqJson.AppliedKitta, " kittas to - ", scrip.CompanyName))
		}
	}

	//closing tag
	Log("\n")
}

func showIntroMsg() {
	Log("----------------------------------------------------------------------------")
	Log("MeroShareMonitor - Monitor and automatically apply to open IPOs in MeroShare")
	Log("----------------------------------------------------------------------------")
}

func EncryptAES(key []byte, message string) (encoded string, err error) {
	//Create byte array from the input string
	plainText := []byte(message)

	//Create a new AES cipher using the key
	block, err := aes.NewCipher(key)

	//IF NewCipher failed, exit:
	if err != nil {
		return
	}

	//Make the cipher text a byte array of size BlockSize + the length of the message
	cipherText := make([]byte, aes.BlockSize+len(plainText))

	//iv is the ciphertext up to the blocksize (16)
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	//Encrypt the data:
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	//Return string encoded in base64
	return base64.RawStdEncoding.EncodeToString(cipherText), err
}

func DecryptAES(key []byte, secure string) (decoded string, err error) {
	//Remove base64 encoding:
	cipherText, err := base64.RawStdEncoding.DecodeString(secure)

	//IF DecodeString failed, exit:
	if err != nil {
		return
	}

	//Create a new AES cipher with the key and encrypted message
	block, err := aes.NewCipher(key)

	//IF NewCipher failed, exit:
	if err != nil {
		return
	}

	//IF the length of the cipherText is less than 16 Bytes:
	if len(cipherText) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short!")
		return
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	//Decrypt the message
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), err
}

// reads the key file corresponding to the given profile number
func GetKey(configFileName string) ([]byte, error) {
	keyPath := "key_" + configFileName + ".dat"
	key, err := os.ReadFile(keyPath)
	return key, err
}

// creates a random 32-digit key and writes to a key file corresponding to the given profile number
func MakeKey(configFileName string) error {
	keyPath := "key_" + configFileName + ".dat"
	randStr := randString(32)
	error_ := os.WriteFile(keyPath, []byte(randStr), 0644)
	return error_
}

func randString(n int) string {
	const alphanum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@+=[{}];:,./~!@#$%^&*()_"
	symbols := big.NewInt(int64(len(alphanum)))
	states := big.NewInt(0)
	states.Exp(symbols, big.NewInt(int64(n)), nil)
	r, err := rand.Int(rand.Reader, states)
	if err != nil {
		panic(err)
	}
	var bytes = make([]byte, n)
	r2 := big.NewInt(0)
	symbol := big.NewInt(0)
	for i := range bytes {
		r2.DivMod(r, symbols, symbol)
		r, r2 = r2, r
		bytes[i] = alphanum[symbol.Int64()]
	}
	return string(bytes)
}

func GetClientIds() map[string]string {
	//map of "depository participant id" : "clientId"
	clientIdDict := map[string]string{
		"13200": "128",
		"12300": "129",
		"17200": "130",
		"11900": "131",
		"15600": "132",
		"17500": "201",
		"14700": "133",
		"11100": "134",
		"15000": "135",
		"16000": "136",
		"11700": "137",
		"10100": "138",
		"13300": "139",
		"13400": "140",
		"12000": "141",
		"14500": "142",
		"11300": "143",
		"14900": "144",
		"10800": "145",
		"17600": "153",
		"12200": "151",
		"11200": "146",
		"16200": "147",
		"18000": "681",
		"17700": "148",
		"17400": "149",
		"13100": "150",
		"17900": "402",
		"18200": "1182",
		"14300": "154",
		"15200": "156",
		"10700": "157",
		"13800": "158",
		"16100": "159",
		"14100": "155",
		"16700": "160",
		"13600": "161",
		"17300": "162",
		"12500": "199",
		"15900": "163",
		"16800": "198",
		"15100": "166",
		"10400": "164",
		"16400": "165",
		"15700": "167",
		"16300": "168",
		"15500": "169",
		"15300": "170",
		"11500": "171",
		"10200": "172",
		"10600": "173",
		"13700": "174",
		"11000": "175",
		"11800": "176",
		"17000": "177",
		"13900": "178",
		"12600": "179",
		"14800": "180",
		"16900": "181",
		"15400": "152",
		"12800": "182",
		"18600": "1270",
		"16600": "183",
		"16500": "184",
		"18100": "1080",
		"14400": "185",
		"15800": "186",
		"11600": "187",
		"12700": "188",
		"18400": "1189",
		"18500": "1196",
		"12900": "189",
		"10900": "190",
		"14600": "191",
		"13000": "192",
		"14000": "193",
		"14200": "194",
		"17800": "370",
		"12400": "195",
		"18300": "1186",
		"11400": "196",
		"17100": "197",
		"13500": "200",
	}
	return clientIdDict
}

func GetTimestamp() string {
	now := time.Now()
	timestamp := now.Unix()
	return strconv.Itoa(int(timestamp))
}

func Log(msg string) {
	fmt.Println(msg)
	file, err := os.OpenFile("MeroshareMonitor-Log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Cannot write to log file!")
	} else {
		t := time.Now()
		timestamp := t.Format("2006-01-02 03:04:05 PM")
		file.WriteString("[" + timestamp + "] " + msg + "\n")
	}

}

func Panic(msg string) {
	Log(msg)
	panic(msg)
}
