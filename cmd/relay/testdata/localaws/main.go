// Test-only AWS CLI boundary adapter. Never installed in a release image.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/zksecurity/relay/internal/teststore"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func run() error {
	args := os.Args[1:]
	opts := map[string]string{}
	op := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "s3api" && i+1 < len(args) {
			op = args[i+1]
		}
		if strings.HasPrefix(args[i], "--") && i+1 < len(args) {
			opts[args[i]] = args[i+1]
		}
	}
	r := teststore.Request{Args: args, Key: os.Getenv("AWS_ACCESS_KEY_ID"), Secret: os.Getenv("AWS_SECRET_ACCESS_KEY"), Token: os.Getenv("AWS_SESSION_TOKEN")}
	if p := opts["--profile"]; p != "" {
		b, e := os.ReadFile(os.Getenv("AWS_SHARED_CREDENTIALS_FILE"))
		if e != nil {
			return e
		}
		active := false
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "[") {
				active = line == "["+p+"]"
				continue
			}
			if !active {
				continue
			}
			kv := strings.SplitN(line, "=", 2)
			if len(kv) != 2 {
				continue
			}
			switch strings.TrimSpace(kv[0]) {
			case "aws_access_key_id":
				r.Key = strings.TrimSpace(kv[1])
			case "aws_secret_access_key":
				r.Secret = strings.TrimSpace(kv[1])
			}
		}
	}
	if op == "put-object" {
		f, e := os.Open(opts["--body"])
		if e != nil {
			return e
		}
		defer f.Close()
		r.Body, e = io.ReadAll(io.LimitReader(f, teststore.Limit+1))
		if e != nil {
			return e
		}
		if len(r.Body) > teststore.Limit {
			return fmt.Errorf("tiny fixture size exceeded")
		}
	}
	ca, e := os.ReadFile(os.Getenv("LOCAL_STORE_CA"))
	if e != nil {
		return e
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return fmt.Errorf("invalid local CA")
	}
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	c := http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("redirect refused") }}
	res, e := c.Post(os.Getenv("LOCAL_STORE_URL")+"/adapter", "application/json", bytes.NewReader(b))
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("local adapter HTTP %d", res.StatusCode)
	}
	var out teststore.Response
	if e = json.NewDecoder(io.LimitReader(res.Body, 2*teststore.Limit)).Decode(&out); e != nil {
		return e
	}
	if out.Error != "" {
		return fmt.Errorf("%s", out.Error)
	}
	if op == "get-object" {
		if len(args) == 0 {
			return fmt.Errorf("missing destination")
		}
		f, e := os.OpenFile(args[len(args)-1], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(out.Body)
		ce := f.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
	}
	_, e = os.Stdout.Write(append(out.Output, '\n'))
	return e
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
