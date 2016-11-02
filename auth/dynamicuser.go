// Copyright 2016 Apcera Inc. All rights reserved.

package auth

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/nats-io/gnatsd/server"

	"io/ioutil"
	"net/http"
)

const (
	pwc   = '*'
	fwc   = '>'
	tsep  = "."
	btsep = '.'
)

// Plain authentication is a basic username and password
type DynamicUser struct {
	users                map[string]*server.User
	authenticatorhub     *server.AuthenticatorHub
	authenticatorHubConn *nats.Conn
}

type AuthenticatorStatus struct {
	status string
}

// Create a new multi-user
func NewDynamicUser(users []*server.User, authenticatorhub *server.AuthenticatorHub) *DynamicUser {
	nc, err := authenticatorHubConnect(authenticatorhub)
	if err != nil {
		fmt.Errorf("AuthenticatorHub Connection Failed: ", err)
	}

	m := &DynamicUser{users: make(map[string]*server.User), authenticatorHubConn: nc}
	for _, u := range users {
		if u.Username != "" {
			m.users[u.Username] = u
		} else if u.Token != "" {
			m.users[u.Token] = u
		}
	}

	m.authenticatorhub = authenticatorhub
	m.authenticatorHubConn = nc
	return m
}

// Check authenticates the server using dynamic auth.
func (m *DynamicUser) Check(c server.ClientAuth) bool {
	opts := c.GetOpts()

	//Todo: token??
	if authAuthenticatorRequest(m.authenticatorhub.AuthAuthenticator, opts.Username, opts.Password) {
		user := m.users[opts.Username]
		user.Username = opts.Username
		user.Password = opts.Password
		user.Token = opts.Token
		c.RegisterUser(user)

		return true
	}

	return false
}

func authAuthenticatorRequest(authAuthenticatorUrl string, username string, password string) bool {
	timeout := time.Duration(5 * time.Second)
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
		server.Errorf("authAuthenticatorRequest Error: %v", err)
		return false
	}

	server.Debugf("authAuthenticatorRequest Body: %v", string(body))

	authenticatorStatus := &AuthenticatorStatus{status: ""}
	err = json.Unmarshal(msg.Data, &authenticatorStatus)
	if err != nil {
		server.Errorf("authAuthenticatorRequest Error: %v", err)
		return false
	}

	if authenticatorStatus.status != "true" {
		server.Errorf("authAuthenticatorRequest Failed")
		return false
	}

	return true
}
