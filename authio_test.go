package authio

import "testing"

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
