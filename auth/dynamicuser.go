// Copyright 2016 Apcera Inc. All rights reserved.

package auth

import (
	"encoding/json"
	"time"

	"github.com/nats-io/gnatsd/server"
	"golang.org/x/crypto/bcrypt"

	"io/ioutil"
	"net/http"
	"net/url"
)

// Plain authentication is a basic username and password
type DynamicUser struct {
	users            map[string]*server.User
	authenticatorhub *server.AuthenticatorHub
	authTimeout      float64
}

type AuthenticatorStatus struct {
	Status string
}

// Create a new multi-user
func NewDynamicUser(users []*server.User, authenticatorhub *server.AuthenticatorHub, authTimeout float64) *DynamicUser {

	m := &DynamicUser{users: make(map[string]*server.User)}
	for _, u := range users {
		if u.Username != "" {
			m.users[u.Username] = u
		} else if u.Token != "" {
			m.users[u.Token] = u
		}
	}

	m.authenticatorhub = authenticatorhub
	m.authTimeout = authTimeout
	return m
}

// Check authenticates the server using dynamic auth.
func (m *DynamicUser) Check(c server.ClientAuth) bool {
	opts := c.GetOpts()

	//Todo: token??
	if opts.Authorization == "" && opts.Username == "" {
		return false
	}

	user := m.users[opts.Username]
	if user != nil {
		if !passAuth(user.Password, opts.Password) {
			return false
		}

		c.RegisterUser(user)

		return true
	} else if authAuthenticatorRequest(m.authenticatorhub.AuthAuthenticator, opts.Username, opts.Password, opts.Authorization, m.authTimeout) {
		user = &server.User{Username: opts.Username, Password: opts.Password, Permissions: nil, Token: opts.Authorization}
		c.RegisterUser(user)

		return true
	}

	return false
}

// Check authenticates the server using dynamic auth.
func (m *DynamicUser) CheckSub(c server.ClientAuth, subject string) bool {
	opts := c.GetOpts()

	//Todo: token??
	if subAuthenticatorRequest(m.authenticatorhub.SubAuthenticator, opts.Username, opts.Authorization, subject, m.authTimeout) {
		return true
	}

	return false
}

// Check authenticates the server using dynamic auth.
func (m *DynamicUser) CheckPub(c server.ClientAuth, subject string) bool {
	opts := c.GetOpts()

	//Todo: token??
	if pubAuthenticatorRequest(m.authenticatorhub.PubAuthenticator, opts.Username, opts.Authorization, subject, m.authTimeout) {
		return true
	}

	return false
}

func passAuth(configPass string, userPass string) bool {
	// Check to see if the password is a bcrypt hash
	if isBcrypt(configPass) {
		if err := bcrypt.CompareHashAndPassword([]byte(configPass), []byte(userPass)); err != nil {
			return false
		}
	} else if configPass != userPass {
		return false
	}
	return true
}

func authAuthenticatorRequest(authAuthenticatorUrl string, username string, password string, token string, authTimeout float64) bool {
	timeout := time.Duration(authTimeout * float64(time.Second))
	client := http.Client{
		Timeout: timeout,
	}

	values := url.Values{}
	if token != "" {
		values = url.Values{"token": {token}}
	} else {
		values = url.Values{"username": {username}, "password": {password}}
	}
	resp, err := client.PostForm(authAuthenticatorUrl, values)

	if err != nil {
		server.Errorf("authAuthenticatorRequest Error: %v", err)
		return false
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		server.Errorf("authAuthenticatorRequest Responese Body Error: %v", err)
		return false
	}
	server.Debugf("authAuthenticatorRequest Body: %v", string(body))
	server.Noticef("authAuthenticatorRequest Body: %v", string(body))

	authenticatorStatus := AuthenticatorStatus{Status: ""}
	err = json.Unmarshal(body, &authenticatorStatus)
	if err != nil {
		server.Errorf("authAuthenticatorRequest Json Parse Error: %v", err)
		return false
	}

	if authenticatorStatus.Status != "success" {
		server.Errorf("authAuthenticatorRequest Failed")
		return false
	}

	return true
}

func subAuthenticatorRequest(authAuthenticatorUrl string, username string, token string, subject string, authTimeout float64) bool {
	timeout := time.Duration(authTimeout * float64(time.Second))
	client := http.Client{
		Timeout: timeout,
	}

	values := url.Values{}
	if token != "" {
		values = url.Values{"token": {token}, "subject": {subject}}
	} else {
		values = url.Values{"username": {username}, "subject": {subject}}
	}
	resp, err := client.PostForm(authAuthenticatorUrl, values)

	if err != nil {
		server.Errorf("subAuthenticatorRequest Error: %v", err)
		return false
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		server.Errorf("subAuthenticatorRequest Responese Body Error: %v", err)
		return false
	}

	server.Debugf("subAuthenticatorRequest Body: %v", string(body))

	authenticatorStatus := &AuthenticatorStatus{Status: ""}
	err = json.Unmarshal(body, &authenticatorStatus)
	if err != nil {
		server.Errorf("subAuthenticatorRequest Json Parse Error: %v", err)
		return false
	}

	if authenticatorStatus.Status != "success" {
		server.Errorf("subAuthenticatorRequest Failed")
		return false
	}

	return true
}

func pubAuthenticatorRequest(authAuthenticatorUrl string, username string, token string, subject string, authTimeout float64) bool {
	timeout := time.Duration(authTimeout * float64(time.Second))
	client := http.Client{
		Timeout: timeout,
	}

	values := url.Values{}
	if token != "" {
		values = url.Values{"token": {token}, "subject": {subject}}
	} else {
		values = url.Values{"username": {username}, "subject": {subject}}
	}
	resp, err := client.PostForm(authAuthenticatorUrl, values)

	if err != nil {
		server.Errorf("pubAuthenticatorRequest Error: %v", err)
		return false
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		server.Errorf("pubAuthenticatorRequest Responese Body Error: %v", err)
		return false
	}

	server.Debugf("pubAuthenticatorRequest Body: %v", string(body))

	authenticatorStatus := &AuthenticatorStatus{Status: ""}
	err = json.Unmarshal(body, &authenticatorStatus)
	if err != nil {
		server.Errorf("pubAuthenticatorRequest Json Parse Error: %v", err)
		return false
	}

	if authenticatorStatus.Status != "success" {
		server.Errorf("pubAuthenticatorRequest Failed")
		return false
	}

	return true
}
