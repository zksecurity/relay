package teststore

import "testing"

func TestPublicationFaultPersistsAcrossRetryAndCountsBodies(t *testing.T) {
	s := New()
	s.Endpoint = "https://test.invalid"
	s.CoordinatorKey = "key"
	s.CoordinatorSecret = "secret"
	put := func(key string) Response {
		return s.Execute(Request{Args: []string{"--endpoint-url", s.Endpoint, "s3api", "put-object", "--bucket", "published", "--key", key, "--if-none-match", "*"}, Key: s.CoordinatorKey, Secret: s.CoordinatorSecret, Body: []byte("public")})
	}
	s.ArmPublicationFault()
	if r := put("one"); r.Error != "" {
		t.Fatal(r.Error)
	}
	for i := 0; i < 2; i++ {
		if r := put("two"); r.Error != "InjectedPublicationFailure" {
			t.Fatal(r)
		}
	}
	f := s.PublicationFault(true)
	if !f.Failed || f.Successful != "published/one" || f.Attempts["published/two"] != 2 {
		t.Fatal(f)
	}
	if r := put("two"); r.Error != "" {
		t.Fatal(r.Error)
	}
	if r := put("one"); r.Error != "PreconditionFailed" {
		t.Fatal(r)
	}
	if f := s.PublicationFault(false); f.Attempts["published/one"] != 2 {
		t.Fatal("lost retransmission count", f)
	}
}
