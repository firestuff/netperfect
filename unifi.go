package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

type Client struct {
	http_client *http.Client
	base_url string
}

func NewClient(base_url string) (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &Client{
		http_client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Jar: jar,
		},
		base_url: base_url,
	}, nil
}

type Creds struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ErrorResp struct {
	Errors []string
}

func (c *Client) Login() error {
	needSave := false

	creds, err := loadCreds()
	if err != nil {
		creds, err = promptCreds()
		if err != nil {
			return err
		}
		needSave = true
	}

	body, err := json.Marshal(creds)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/auth/login", c.base_url), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http_client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		dec := json.NewDecoder(resp.Body)
		error_resp := ErrorResp{}
		err = dec.Decode(&error_resp)
		if err != nil {
			return err
		}
		return fmt.Errorf("Failed to log into UniFi with saved credentials (\"%s\"). Delete %s to prompt again.", error_resp.Errors[0], credPath())
	}

	log.Printf("Logged into UniFi as %s", creds.Username)

	if needSave {
		err = creds.Save()
		if err != nil {
			return err
		}
	}

	return nil
}

func loadCreds() (*Creds, error) {
	fh, err := os.OpenFile(credPath(), os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	dec := yaml.NewDecoder(fh)

	ret := &Creds{}

	err = dec.Decode(ret)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func promptCreds() (*Creds, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("UniFi username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	fmt.Print("UniFi password: ")
	password, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	return &Creds{
		Username: strings.TrimSuffix(username, "\n"),
		Password: strings.TrimSuffix(password, "\n"),
	}, nil
}

func (c *Creds) Save() error {
	fh, err := os.OpenFile(credPath(), os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer fh.Close()

	enc := yaml.NewEncoder(fh)
	defer enc.Close()

	err = enc.Encode(c)
	if err != nil {
		return err
	}

	log.Printf("Saved credentials to %s", credPath())

	return nil
}

func credPath() string {
	return path.Join(os.Getenv("HOME"), ".netperfect.creds")
}