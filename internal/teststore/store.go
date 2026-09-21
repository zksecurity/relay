// Package teststore is a tiny-rehearsal storage adapter, NOT an S3/R2 emulator.
// It is imported only by tests and their testdata executable. No cloud fallback.
package teststore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const Limit = 64 << 20

type Request struct {
	Args               []string
	Key, Secret, Token string
	Body               []byte
}
type Response struct {
	Output json.RawMessage
	Body   []byte
	Error  string
}
type object struct {
	body          []byte
	etag, version string
}
type Server struct {
	mu                                                                            sync.Mutex
	objects                                                                       map[string]object
	counter                                                                       uint64
	Endpoint, CoordinatorKey, CoordinatorSecret, ParentKey, ParentSecret, Account string
}

func New() *Server { return &Server{objects: map[string]object{}} }
func options(args []string) (string, map[string]string, error) {
	m := map[string]string{}
	op := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "s3api" {
			if i+1 == len(args) {
				return "", nil, errors.New("missing operation")
			}
			i++
			op = args[i]
			continue
		}
		if a == "--no-sign-request" {
			m[a] = "true"
			continue
		}
		if !strings.HasPrefix(a, "--") {
			continue
		}
		if i+1 == len(args) {
			return "", nil, errors.New("missing option")
		}
		i++
		m[a] = args[i]
	}
	return op, m, nil
}
func clean(k string) bool {
	return k != "" && path.Clean(k) == k && !strings.HasPrefix(k, "/") && k != ".." && !strings.HasPrefix(k, "../") && !strings.ContainsAny(k, "\\\x00\r\n")
}
func (s *Server) authorize(r Request, m map[string]string, key string) bool {
	if m["--endpoint-url"] != s.Endpoint || m["--no-sign-request"] != "" {
		return false
	}
	if s.CoordinatorKey != "" && s.CoordinatorSecret != "" && r.Key == s.CoordinatorKey && hmac.Equal([]byte(r.Secret), []byte(s.CoordinatorSecret)) && r.Token == "" {
		return true
	}
	if r.Key != s.ParentKey {
		return false
	}
	token, e := base64.StdEncoding.DecodeString(r.Token)
	if e != nil || !strings.HasPrefix(string(token), "jwt/") {
		return false
	}
	jws := strings.TrimPrefix(string(token), "jwt/")
	p := strings.Split(jws, ".")
	if len(p) != 3 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(s.ParentSecret))
	mac.Write([]byte(p[0] + "." + p[1]))
	sig, e := base64.RawURLEncoding.DecodeString(p[2])
	if e != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return false
	}
	h := sha256.Sum256([]byte(jws))
	if r.Secret != hex.EncodeToString(h[:]) {
		return false
	}
	var header struct{ Alg, Typ string }
	b, e := base64.RawURLEncoding.DecodeString(p[0])
	if e != nil || json.Unmarshal(b, &header) != nil || header.Alg != "HS256" || header.Typ != "JWT" {
		return false
	}
	var c struct {
		Bucket, Scope, Sub, Iss, Aud string
		Iat, Exp                     int64
		Paths                        struct{ PrefixPaths, ObjectPaths []string }
	}
	b, e = base64.RawURLEncoding.DecodeString(p[1])
	if e != nil || json.Unmarshal(b, &c) != nil {
		return false
	}
	if c.Bucket != m["--bucket"] || c.Bucket != "inbox" || c.Scope != "object-read-write" || c.Sub != s.Account || c.Iss != s.ParentKey || c.Aud != strings.TrimPrefix(s.Endpoint, "https://") || c.Exp <= time.Now().Unix() || c.Iat > time.Now().Unix()+120 {
		return false
	}
	for _, p := range c.Paths.PrefixPaths {
		if p != "" && strings.HasPrefix(key, p) {
			return true
		}
	}
	for _, p := range c.Paths.ObjectPaths {
		if p == key {
			return true
		}
	}
	return false
}
func (s *Server) Execute(r Request) Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	fail := func(v string) Response { return Response{Error: v} }
	op, m, e := options(r.Args)
	if e != nil {
		return fail("InvalidRequest")
	}
	bucket, key := m["--bucket"], m["--key"]
	if op == "list-objects-v2" {
		key = m["--prefix"]
	}
	if bucket != "published" && bucket != "inbox" {
		return fail("AccessDenied")
	}
	if !s.authorize(r, m, key) {
		return fail("AccessDenied")
	}
	if op != "list-objects-v2" && !clean(key) {
		return fail("InvalidKey")
	}
	name := bucket + "/" + key
	o, exists := s.objects[name]
	output := func(v any) Response { b, _ := json.Marshal(v); return Response{Output: b} }
	metadata := func(o object) map[string]any {
		return map[string]any{"ETag": o.etag, "VersionId": o.version, "ContentLength": len(o.body)}
	}
	switch op {
	case "put-object":
		if len(r.Body) > Limit {
			return fail("EntityTooLarge")
		}
		if m["--if-none-match"] != "*" && m["--if-match"] == "" {
			return fail("ConditionalWriteRequired")
		}
		if m["--if-none-match"] == "*" && exists || m["--if-match"] != "" && (!exists || o.etag != m["--if-match"]) {
			return fail("PreconditionFailed")
		}
		s.counter++
		h := sha256.Sum256(r.Body)
		o = object{append([]byte(nil), r.Body...), fmt.Sprintf("\"%x-%d\"", h, s.counter), strconv.FormatUint(s.counter, 10)}
		s.objects[name] = o
		return output(metadata(o))
	case "head-object", "get-object":
		if !exists {
			return fail("NoSuchKey (404)")
		}
		if m["--if-match"] != "" && m["--if-match"] != o.etag || m["--version-id"] != "" && m["--version-id"] != o.version {
			return fail("PreconditionFailed")
		}
		if op == "head-object" && m["--query"] == "ContentLength" {
			return output(len(o.body))
		}
		result := output(metadata(o))
		if op == "head-object" {
			return result
		}
		b := o.body
		if v := m["--range"]; v != "" {
			var start, end int
			if _, e := fmt.Sscanf(v, "bytes=%d-%d", &start, &end); e != nil || start < 0 || end < start || start >= len(b) {
				return fail("InvalidRange")
			}
			if end >= len(b) {
				end = len(b) - 1
			}
			b = b[start : end+1]
		}
		result.Body = append([]byte(nil), b...)
		return result
	case "delete-object":
		delete(s.objects, name)
		return output(map[string]any{})
	case "list-objects-v2":
		if key != "" && !clean(strings.TrimSuffix(key, "/")) {
			return fail("InvalidKey")
		}
		names := []string{}
		for n := range s.objects {
			if strings.HasPrefix(n, bucket+"/"+key) {
				names = append(names, strings.TrimPrefix(n, bucket+"/"))
			}
		}
		sort.Strings(names)
		start := 0
		if v := m["--continuation-token"]; v != "" {
			start, e = strconv.Atoi(v)
			if e != nil || start < 0 || start > len(names) {
				return fail("InvalidToken")
			}
		}
		end := start + 100
		if end > len(names) {
			end = len(names)
		}
		items := []map[string]any{}
		for _, n := range names[start:end] {
			items = append(items, map[string]any{"Key": n, "Size": len(s.objects[bucket+"/"+n].body)})
		}
		return output(map[string]any{"Contents": items, "IsTruncated": end < len(names), "NextContinuationToken": strconv.Itoa(end)})
	default:
		return fail("UnsupportedOperation")
	}
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" && r.URL.Path == "/adapter" {
		var in Request
		d := json.NewDecoder(io.LimitReader(r.Body, 2*Limit))
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil {
			http.Error(w, "bad request", 400)
			return
		}
		json.NewEncoder(w).Encode(s.Execute(in))
		return
	}
	if r.Method != "GET" || !strings.HasPrefix(r.URL.Path, "/published/") {
		http.NotFound(w, r)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/published/")
	if !clean(key) {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	o, ok := s.objects["published/"+key]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("ETag", o.etag)
	w.Header().Set("Content-Length", strconv.Itoa(len(o.body)))
	w.Write(o.body)
}
