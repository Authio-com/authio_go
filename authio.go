// Package authio is the official Go server SDK for the Authio
// authentication platform. Multi-org-first: Session.UserID identifies the
// person; Session.OrgID is the active organization (may be empty if the
// user has authenticated but not yet selected an org).
package authio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	defaultBaseURL = "https://api.authio.com"
)

// Client is the entrypoint for server-side calls into Authio.
type Client struct {
	APIKey  string
	BaseURL string
	HTTP    *http.Client
}

// New constructs a Client with sensible defaults. APIKey is required.
func New(apiKey string, opts ...Option) (*Client, error) {
	if apiKey == "" {
		return nil, errors.New("authio: APIKey is required")
	}
	c := &Client{APIKey: apiKey, BaseURL: defaultBaseURL, HTTP: http.DefaultClient}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

type Option func(*Client)

func WithBaseURL(u string) Option       { return func(c *Client) { c.BaseURL = strings.TrimRight(u, "/") } }
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.HTTP = h } }

// User mirrors the Authio User entity.
type User struct {
	ID                    string `json:"id"`
	ProjectID             string `json:"project_id"`
	Email                 string `json:"email"`
	EmailVerified         bool   `json:"email_verified"`
	Name                  string `json:"name,omitempty"`
	AvatarURL             string `json:"avatar_url,omitempty"`
	DefaultOrganizationID string `json:"default_organization_id,omitempty"`
}

// Organization mirrors the Authio Organization entity.
type Organization struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
}

// MembershipStatus enumerates membership lifecycle states.
type MembershipStatus string

const (
	MembershipStatusInvited     MembershipStatus = "invited"
	MembershipStatusActive      MembershipStatus = "active"
	MembershipStatusSuspended   MembershipStatus = "suspended"
	MembershipStatusDeactivated MembershipStatus = "deactivated"
)

// Membership ties a User to an Organization with a role.
type Membership struct {
	ID                   string           `json:"id"`
	ProjectID            string           `json:"project_id"`
	UserID               string           `json:"user_id"`
	OrganizationID       string           `json:"organization_id"`
	Role                 string           `json:"role"`
	Status               MembershipStatus `json:"status"`
	PreferredLoginMethod string           `json:"preferred_login_method,omitempty"`
}

// Session is the verified session shape returned to your handlers.
type Session struct {
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	OrgID     string `json:"org_id,omitempty"`
	Role      string `json:"role,omitempty"`
}

// =====================================================================
// Users
// =====================================================================

func (c *Client) GetUser(ctx context.Context, id string) (*User, error) {
	var u User
	if err := c.do(ctx, http.MethodGet, "/v1/users/"+id, nil, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

func (c *Client) ListMemberships(ctx context.Context, userID string) ([]Membership, error) {
	var ms []Membership
	if err := c.do(ctx, http.MethodGet, "/v1/users/"+userID+"/memberships", nil, &ms); err != nil {
		return nil, err
	}
	return ms, nil
}

// =====================================================================
// Organizations
// =====================================================================

func (c *Client) ListOrganizations(ctx context.Context) ([]Organization, error) {
	var os []Organization
	if err := c.do(ctx, http.MethodGet, "/v1/organizations", nil, &os); err != nil {
		return nil, err
	}
	return os, nil
}

type CreateOrganizationInput struct {
	Name   string `json:"name"`
	Slug   string `json:"slug,omitempty"`
	Domain string `json:"domain,omitempty"`
}

func (c *Client) CreateOrganization(ctx context.Context, in CreateOrganizationInput) (*Organization, error) {
	var o Organization
	if err := c.do(ctx, http.MethodPost, "/v1/organizations", in, &o); err != nil {
		return nil, err
	}
	return &o, nil
}

// =====================================================================
// Memberships
// =====================================================================

type AddMembershipInput struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

func (c *Client) AddMember(ctx context.Context, orgID string, in AddMembershipInput) (*Membership, error) {
	var m Membership
	if err := c.do(ctx, http.MethodPost, "/v1/organizations/"+orgID+"/memberships", in, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (c *Client) RemoveMember(ctx context.Context, orgID, membershipID string) error {
	return c.do(ctx, http.MethodDelete, "/v1/organizations/"+orgID+"/memberships/"+membershipID, nil, nil)
}

// =====================================================================
// Internal HTTP plumbing
// =====================================================================

// Error represents a structured Authio API error.
type Error struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Status    int    `json:"-"`
	RequestID string `json:"request_id,omitempty"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("authio: %s (status=%d, code=%s, request_id=%s)", e.Message, e.Status, e.Code, e.RequestID)
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "authio-go/0.1.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var apiErr Error
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		apiErr.Status = resp.StatusCode
		if apiErr.Code == "" {
			apiErr.Code = "request_failed"
			apiErr.Message = http.StatusText(resp.StatusCode)
		}
		return &apiErr
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
