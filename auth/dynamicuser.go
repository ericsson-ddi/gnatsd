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
}

type AuthenticatorStatus struct {
	Status string
}

// Create a new multi-user
func NewDynamicUser(users []*server.User, authenticatorhub *server.AuthenticatorHub) *DynamicUser {

	m := &DynamicUser{users: make(map[string]*server.User)}
	for _, u := range users {
		if u.Username != "" {
			m.users[u.Username] = u
		} else if u.Token != "" {
			m.users[u.Token] = u
		}
	}

	m.authenticatorhub = authenticatorhub
	return m
}

// Check authenticates the server using dynamic auth.
func (m *DynamicUser) Check(c server.ClientAuth) bool {
	opts := c.GetOpts()

	//Todo: token??
	user := m.users[opts.Username]
	if user != nil {
		pass := user.Password

		// Check to see if the password is a bcrypt hash
		if isBcrypt(pass) {
			if err := bcrypt.CompareHashAndPassword([]byte(pass), []byte(opts.Password)); err != nil {
				return false
			}
		} else if pass != opts.Password {
			return false
		}
		c.RegisterUser(user)

		return true
	} else if authAuthenticatorRequest(m.authenticatorhub.AuthAuthenticator, opts.Username, opts.Password) {
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
	if subAuthenticatorRequest(m.authenticatorhub.SubAuthenticator, opts.Username, subject) {
		return true
	}

	return false
}

// Check authenticates the server using dynamic auth.
func (m *DynamicUser) CheckPub(c server.ClientAuth, subject string) bool {
	opts := c.GetOpts()

	//Todo: token??
	if pubAuthenticatorRequest(m.authenticatorhub.PubAuthenticator, opts.Username, subject) {
		return true
	}

	return false
}

func authAuthenticatorRequest(authAuthenticatorUrl string, username string, password string) bool {
	timeout := time.Duration(25 * time.Millisecond)
	client := http.Client{
		Timeout: timeout,
	}

	resp, err := client.PostForm(authAuthenticatorUrl,
		url.Values{"username": {username}, "password": {password}})

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

func subAuthenticatorRequest(authAuthenticatorUrl string, username string, subject string) bool {
	timeout := time.Duration(15 * time.Millisecond)
	client := http.Client{
		Timeout: timeout,
	}

	resp, err := client.PostForm(authAuthenticatorUrl,
		url.Values{"username": {username}, "sujbect": {subject}})

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

func pubAuthenticatorRequest(authAuthenticatorUrl string, username string, subject string) bool {
	timeout := time.Duration(15 * time.Millisecond)
	client := http.Client{
		Timeout: timeout,
	}

	resp, err := client.PostForm(authAuthenticatorUrl,
		url.Values{"username": {username}, "subject": {subject}})

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
