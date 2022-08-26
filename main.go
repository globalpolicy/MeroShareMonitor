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
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	BOID           string
	Password       string
	CRN            string
	TransactionPIN string
	DefaultBankID  int
	DefaultKittas  int
	SilentMode     bool
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
	BankId          int
	BranchID        int
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
	BankId          int    `json:"bankId"`
	Boid            string `json:"boid"`
	CompanyShareId  string `json:"companyShareId"`
	CrnNumber       string `json:"crnNumber"`
	CustomerId      int    `json:"customerId"`
	Demat           string `json:"demat"`
	TransactionPIN  string `json:"transactionPIN"`
}

func main() {
	showIntroMsg()

	key, keyerror := GetKey()
	if keyerror != nil {
		_ = os.Remove("config.json") //since keyerror occurred, we don't have the key for decrypting config, so delete the old config

		makeKeyErr := MakeKey()
		if makeKeyErr != nil {
			panic("Could not create key file!") //we won't proceed without creating a key file
		}
		var getKeyErr error
		key, getKeyErr = GetKey()
		if getKeyErr != nil {
			panic("Could not read key file!") //we won't proceed without a key
		}
	}

	//at this point, we will have either the old key or a newly created one
	var config Config

	configContents, err := os.ReadFile("config.json")
	if err == nil {
		err = json.Unmarshal(configContents, &config)                             //read the config file into config variable
		config.Password, _ = DecryptAES([]byte(key), config.Password)             //decrypt the saved password
		config.TransactionPIN, _ = DecryptAES([]byte(key), config.TransactionPIN) //decrypt the saved transaction PIN
		config.CRN, _ = DecryptAES([]byte(key), config.CRN)                       //decrypt the saved CRN
	}

	if err != nil { //json read from file is invalid or if file doesn't exist. so ask for user's input
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("Enter your BOID: ")
		boid, _ := reader.ReadString('\n')
		fmt.Println("Enter your password: ")
		password, _ := reader.ReadString('\n')
		fmt.Println("Enter your transaction PIN: ")
		tpin, _ := reader.ReadString('\n')

		config = Config{
			BOID:           strings.TrimSpace(boid),
			Password:       strings.TrimSpace(password),
			TransactionPIN: strings.TrimSpace(tpin),
		}

		fmt.Println("PS: Turn the SilentMode field to true in the config.json file if you want to automatically apply using the saved settings")
	}

	if config.BOID == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("Enter your BOID: ")
		boid, _ := reader.ReadString('\n')
		config.BOID = boid
	}

	if config.Password == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("Enter your password: ")
		pwd, _ := reader.ReadString('\n')
		config.Password = pwd
	}

	if config.TransactionPIN == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("Enter your transaction PIN: ")
		tpin, _ := reader.ReadString('\n')
		config.TransactionPIN = strings.TrimSpace(tpin)
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
	authRequestBody := map[string]interface{}{"clientId": 174, "username": config.BOID, "password": config.Password}
	req, _ := json.Marshal(authRequestBody)
	resp, err := http.Post("https://webbackend.cdsc.com.np/api/meroShare/auth/", "application/json", bytes.NewBuffer(req))
	if err != nil {
		panic("Error authenticating!")
	}
	authToken := resp.Header.Get("Authorization")

	//ask for default bank and its corresponding CRN to apply from
	if config.DefaultBankID == 0 {
		//load bank brief
		request, _ := http.NewRequest("GET", "https://webbackend.cdsc.com.np/api/meroShare/bank/", bytes.NewBufferString(""))
		request.Header.Add("Authorization", authToken)
		client := &http.Client{}
		response, err := client.Do(request)
		if err != nil {
			panic("Error getting banks!")
		}
		defer response.Body.Close()

		var bankBriefs []BankBrief
		err = json.NewDecoder(response.Body).Decode(&bankBriefs)
		if err != nil {
			panic("Error parsing bank briefs JSON!")
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
	_ = os.WriteFile("config.json", serializedData, 0666)

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
	request, _ := http.NewRequest("POST", "https://webbackend.cdsc.com.np/api/meroShare/companyShare/applicableIssue/", bytes.NewBuffer(reqBodyForAvailableIssues))
	request.Header.Add("Authorization", authToken)
	request.Header.Add("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil || response.StatusCode != 200 {
		panic("Error getting applicable issues!")
	}
	defer response.Body.Close()

	var responseJson map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&responseJson)
	if err != nil {
		panic("Error parsing applicable issues JSON!")
	}

	//damned conversion from []interface{} to []AvailableIssueObject{}
	availableScrips := []AvailableIssueObject{}
	availables := responseJson["object"].([]interface{})
	for _, v := range availables {
		tmp := v.(map[string]interface{})
		if _, isKeyPresent := tmp["action"]; isKeyPresent { //there's an "action" key if this scrip was already applied to
			fmt.Println("Skipping recently applied company ", tmp["companyName"].(string))
			continue
		}
		jsonString, _ := json.Marshal(tmp)
		var availableIssue AvailableIssueObject
		err := json.Unmarshal(jsonString, &availableIssue)
		if err != nil {
			panic("Error parsing available scrips!")
		}
		availableScrips = append(availableScrips, availableIssue)
	}

	scripsToApply := []ScripToApply{}
	for _, scrip := range availableScrips {
		if config.SilentMode {
			if scrip.ShareGroupName == "Ordinary Shares" {
				var scripToApply ScripToApply
				scripToApply.BankIdToApply = config.DefaultBankID
				scripToApply.KittasToApply = strconv.Itoa(config.DefaultKittas)
				scripToApply.CompanyShareId = strconv.Itoa(scrip.CompanyShareId)
				scripToApply.CompanyName = scrip.CompanyName
				scripsToApply = append(scripsToApply, scripToApply)
			}
		} else {
			fmt.Println(scrip.CompanyName, "-", scrip.ShareGroupName, "(", scrip.IssueOpenDate, "-", scrip.IssueCloseDate, ")")
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
		fmt.Println("No IPOs open right now. Quitting.")
		return
	}

	//retrieve accountNumber and customerId fields (required to apply) from an API call to get the default bank's details
	request, _ = http.NewRequest("GET", "https://webbackend.cdsc.com.np/api/meroShare/bank/"+strconv.Itoa(config.DefaultBankID), nil)
	request.Header.Add("Authorization", authToken)
	request.Header.Add("Content-Type", "application/json")
	client = &http.Client{}
	response, err = client.Do(request)
	if err != nil || response.StatusCode != 200 {
		panic("Error getting bank details!")
	}
	defer response.Body.Close()
	var bankDetail BankDetail
	err = json.NewDecoder(response.Body).Decode(&bankDetail)
	if err != nil {
		panic("Error parsing bank details JSON!")
	}

	//retrieve demat from another API call
	request, _ = http.NewRequest("GET", "https://webbackend.cdsc.com.np/api/meroShare/ownDetail/", nil)
	request.Header.Add("Authorization", authToken)
	request.Header.Add("Content-Type", "application/json")
	client = &http.Client{}
	response, err = client.Do(request)
	if err != nil || response.StatusCode != 200 {
		panic("Error getting own details!")
	}
	defer response.Body.Close()
	var ownDetail OwnDetail
	err = json.NewDecoder(response.Body).Decode(&ownDetail)
	if err != nil {
		panic("Error parsing own details JSON!")
	}

	//apply to the companies in scripstoApply slice
	applyReqJson := &ApplyScripPayloadJSON{
		AccountBranchId: bankDetail.AccountBranchId,
		AccountNumber:   bankDetail.AccountNumber,
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
			fmt.Println("Cannot build apply JSON payload!")
		}
		request, _ = http.NewRequest("POST", "https://webbackend.cdsc.com.np/api/meroShare/applicantForm/share/apply", bytes.NewBuffer(reqjson))
		request.Header.Add("Authorization", authToken)
		request.Header.Add("Content-Type", "application/json")
		client = &http.Client{}
		response, err = client.Do(request)
		if err != nil || response.StatusCode != 201 {
			panic("Error applying to scrip!")
		} else {
			fmt.Println("Applied ", applyReqJson.AppliedKitta, " kittas to - ", scrip.CompanyName)
		}
	}
}

func showIntroMsg() {
	fmt.Println("----------------------------------------------------------------------------")
	fmt.Println("MeroShareMonitor - Monitor and automatically apply to open IPOs in MeroShare")
	fmt.Println("----------------------------------------------------------------------------")
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

func GetKey() ([]byte, error) {
	keyPath := os.TempDir() + "\\key.dat"
	key, err := os.ReadFile(keyPath)
	return key, err
}

func MakeKey() error {
	keyPath := os.TempDir() + "\\key.dat"
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