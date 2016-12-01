// Copyright 2016 Apcera Inc. All rights reserved.

package auth

import (
	"github.com/nats-io/gnatsd/server"
	"golang.org/x/crypto/bcrypt"

	"github.com/nats-io/gnatsd/extension"
)

// Plain authentication is a basic username and password
type MultiUser struct {
	users map[string]*server.User
}

// Create a new multi-user
func NewMultiUser(users []*server.User) *MultiUser {
	m := &MultiUser{users: make(map[string]*server.User)}
	for _, u := range users {
		m.users[u.Username] = u
	}
	return m
}

// Check authenticates the client using a username and password against a list of multiple users.
func (m *MultiUser) Check(c server.ClientAuth) bool {
	opts := c.GetOpts()
	user, ok := m.users[opts.Username]
	if !ok {
		user, ok = m.users["EXTENSION"]
		if ok { // check extension user
			if extension, ok := extension.CheckExtensionUser(user.Extension, opts.Username, opts.Password, opts.Authorization); ok {
				extensionUser := &server.User{Username: opts.Username, Password: opts.Password, Permissions: user.Permissions, Extension: extension}
				c.RegisterUser(extensionUser)
				return true
			}
		}
		return false
	}

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
}

