package main

import (
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type WebSshOptions struct {
	Hostname       string `json:"hostname" form:"hostname" query:"hostname"`
	Port           string `json:"port" form:"port" query:"port"`
	Username       string `json:"username" form:"username" query:"username"`
	Authentication string `json:"authentication" form:"authentication" query:"authentication"`
	Password       string `json:"password" form:"password" query:"password"`
	Interactive    string `json:"interactive" form:"interactive" query:"interactive"`
	PrivateKey     string `json:"privatekey" form:"privatekey" query:"privatekey"`
	Passphrase     string `json:"passphrase" form:"passphrase" query:"passphrase"`
}

type WebSshClient struct {
	// The websocket client
	Connection *websocket.Conn
	// The SSH session
	Client *ssh.Client
}
