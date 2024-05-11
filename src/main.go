package main

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"log/slog"
	"time"

	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/teris-io/shortid"
	"golang.org/x/crypto/ssh"
)

var addr = flag.String("addr", "localhost:8080", "http service address")
var upgrader = websocket.Upgrader{} // use default options
var connections = make(map[string]*WebSshClient)

func main() {
	flag.Parse()
	e := echo.New()

	// Set up logging
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogStatus:   true,
		LogURI:      true,
		LogError:    true,
		HandleError: true, // forwards error to the global error handler, so it can decide appropriate status code
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			if v.Error == nil {
				slog.LogAttrs(context.Background(), slog.LevelInfo, "REQUEST",
					slog.String("uri", v.URI),
					slog.Int("status", v.Status),
				)
			} else {
				slog.LogAttrs(context.Background(), slog.LevelError, "REQUEST_ERROR",
					slog.String("uri", v.URI),
					slog.Int("status", v.Status),
					slog.String("err", v.Error.Error()),
				)
			}
			return nil
		},
	}))

	// Set up routes
	e.Static("/", "static")
	e.File("/favicon.ico", "static/assets/favicon.ico")
	e.Static("/console", "console")
	e.POST("/create", create)
	e.GET("/ws/:sessionId", ws)

	// Start the server
	e.Start(*addr)
}

func create(e echo.Context) error {
	var options WebSshOptions
	if err := e.Bind(&options); err != nil {
		return err
	}
	slog.Info("Create request", "Options", options)

	if options.Hostname == "" {
		return e.String(400, "Hostname is required")
	}
	if options.Port == "" {
		options.Port = "22"
	}
	if options.Username == "" {
		return e.String(400, "Username is required")
	}
	if options.Authentication == "0" && options.Password == "" {
		return e.String(400, "Password is required")
	} else if options.Authentication == "1" && (options.PrivateKey == "" || options.Passphrase == "") {
		return e.String(400, "Private key & passphrase are required")
	}

	var method ssh.AuthMethod

	switch options.Authentication {
	case "0":
		if options.Interactive == "" {
			method = ssh.Password(options.Password)
		} else {
			method = ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
				answers = make([]string, len(questions))
				// The second parameter is unused
				for n := range questions {
					answers[n] = options.Password
				}
				return answers, nil
			})
		}
	case "1":
		return e.String(400, "Public key authentication is not supported yet")

	default:
		return e.String(400, "Invalid authentication method")
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", options.Hostname, options.Port), &ssh.ClientConfig{
		User: options.Username,
		Auth: []ssh.AuthMethod{
			method,
		},
		Timeout:         10 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Config: ssh.Config{
			Ciphers: []string{"aes128-ctr", "aes192-ctr", "aes256-ctr", "arcfour256", "arcfour128", "aes128-cbc", "3des-cbc", "blowfish-cbc", "cast128-cbc", "aes192-cbc", "aes256-cbc", "arcfour"},
		},
	})
	if err != nil {
		slog.Error("SSH dial failed", "Error", err)
		return e.String(500, "SSH dial failed")
	}

	sessionId := shortid.MustGenerate()
	connections[sessionId] = &WebSshClient{Connection: nil, Client: client}

	e.Redirect(302, "/console/index.html?"+sessionId)
	return nil
}

func ws(e echo.Context) error {
	sessionId := e.Param("sessionId")
	if sessionId == "" {
		slog.Error("Session ID is required")
		return e.String(400, "Session ID is required")
	}
	c, err := upgrader.Upgrade(e.Response().Writer, e.Request(), nil)
	if err != nil {
		slog.Error("Upgrade failed", "Error", err)
		return err
	}
	defer c.Close()

	webssh := connections[sessionId]
	if webssh == nil {
		slog.Error("WebSSH client not found", "sessionId", sessionId)
		return e.String(400, "WebSSH client not found")
	}
	webssh.Connection = c

	defer webssh.Client.Close()

	session, err := webssh.Client.NewSession()
	if err != nil {
		slog.Error("Create session failed", "Error", err)
		return e.String(500, "Create session failed")
	}
	defer session.Close()

	session.Stdout = c.NetConn()
	session.Stderr = c.NetConn()

	// TODO: Figure our concurrency for StdOut, StdErr, and StdIn

	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			slog.Error("Read message failed", "Error", err)
			break
		}
		slog.Info("Message received", "RemoteAddr", c.RemoteAddr, "Message", message, "Type", mt)
		err = c.WriteMessage(mt, message)
		if err != nil {
			slog.Error("Write message failed", "Error", err)
			break
		}
	}

	return nil
}
