package remote

import (
	"time"
	"net/http"
	"io/ioutil"
	"encoding/json"

	"bytes"
	"fmt"
)

type RemoteAuth struct {
}

func (t *RemoteAuth) Check(extension map[string]string, username string, password string, clientToken string) (bool){
	url := extension["check_user_url"]

	timeout := time.Duration(30 * float64(time.Second))
	client := http.Client{
		Timeout: timeout,
	}

	values := map[string]string{"": ""}
	if clientToken != "" {
		values = map[string]string{"token": clientToken}
	} else {
		values = map[string]string{"username": username, "password": password}
	}

	jsonValue, _ := json.Marshal(values)
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonValue))

	if err != nil {
		fmt.Errorf("authAuthenticatorRequest Error: %v", err)
		return false
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Errorf("authAuthenticatorRequest Responese Body Error: %v", err)
		return false
	}

	fmt.Println("authAuthenticatorRequest Body: " + string(body))

	authResponse := make(map[string]string)
	err = json.Unmarshal(body, &authResponse)
	if err != nil {
		fmt.Errorf("authAuthenticatorRequest Json Parse Error: %v", err)
		return false
	}

	if resp.StatusCode != 200 || authResponse["token"] == "" {
		fmt.Errorf("authAuthenticatorRequest Failed")
		return false
	}

	extension["token"] = authResponse["token"];
	return true
}

