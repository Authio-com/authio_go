package authio

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewRequiresAPIKey(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Fatal("expected error")
	}
}

func TestNewWithBaseURL(t *testing.T) {
	c, err := New("sk_test_x", WithBaseURL("https://api.example/"))
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL != "https://api.example" {
		t.Fatalf("BaseURL trim failed: %s", c.BaseURL)
	}
}

func TestErrorString(t *testing.T) {
	e := &Error{Code: "x", Message: "boom", Status: 418, RequestID: "r1"}
	if e.Error() == "" {
		t.Fatal("empty error")
	}
}

func TestPathIDsAreEscaped(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.EscapedPath())
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c, err := New("sk_test_x", WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	evil := "../../admin?x=1#"
	_, _ = c.GetUser(ctx, evil)
	_, _ = c.ListMemberships(ctx, evil)
	_ = c.RemoveMember(ctx, "o/1", "m/../2")
	want := []string{
		"/v1/users/..%2F..%2Fadmin%3Fx=1%23",
		"/v1/users/..%2F..%2Fadmin%3Fx=1%23/memberships",
		"/v1/organizations/o%2F1/memberships/m%2F..%2F2",
	}
	if len(paths) != len(want) {
		t.Fatalf("got %v", paths)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Fatalf("path %d: got %q want %q", i, paths[i], want[i])
		}
	}
}
