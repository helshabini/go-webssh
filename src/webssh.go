package main

import (
	"io"

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
	// The SSH client
	Client *ssh.Client
	// The SSH session
	Session *ssh.Session
	// Session Writer
	Writer io.WriteCloser
	// Session Reader
	Reader io.Reader
	// Done channel
	Done chan struct{}
}

func NewWebSshClient() *WebSshClient {
	return &WebSshClient{
		Connection: nil,
		Client:     nil,
		Session:    nil,
		Writer:     nil,
		Reader:     nil,
		Done:       make(chan struct{}, 1),
	}
}

type Resize struct {
	Width  int `json:"cols"`
	Height int `json:"rows"`
}
