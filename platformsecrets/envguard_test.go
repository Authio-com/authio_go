package platformsecrets

import (
	"strings"
	"testing"
)

// Shared with the TypeScript implementation's tests.
const (
	exampleKeyID  = "AKIAEXAMPLEEXAMPLE00"
	exampleDigest = "86041fb2a0bbc6c0d6cb70abe7d9173e15c2f4637b8881094da52b2be9899b43"
)

func setEnv(t *testing.T, railway, authio string) {
	t.Helper()
	t.Setenv("RAILWAY_ENVIRONMENT_NAME", railway)
	t.Setenv("AUTHIO_ENV", authio)
	t.Setenv(envGuardWarnOnlyVar, "")
	t.Setenv(envGuardDenylistVar, "")
}

func TestDenylistDigest(t *testing.T) {
	if got := denylistDigest(exampleKeyID); got != exampleDigest {
		t.Fatalf("denylistDigest = %s, want %s", got, exampleDigest)
	}
	for h := range productionDenylist {
		if len(h) != 64 || strings.ToLower(h) != h {
			t.Fatalf("denylist entry %q is not lowercase sha256 hex", h)
		}
	}
}

func TestFindViolations(t *testing.T) {
	extra := map[string]struct{}{exampleDigest: {}}
	vars := map[string]string{
		"AUDIT_SQS_QUEUE_URL":    "https://sqs.us-east-1.amazonaws.com/123456789012/authio-audit-events-production.fifo",
		"AUTHIO_BRANDING_BUCKET": "authio-production-branding",
		"AUTHIO_KMS_KEY_ID":      "alias/authio-production-envelope",
		"AUTHIO_AWS_SECRET_IDS":  "authio/e2e/platform/internal,authio/production/platform/project-keys",
		"STATUS_SNAPSHOT_URL":    "https://authio-production-status-snapshot.s3.us-east-1.amazonaws.com/status/snapshot.json",
		"SES_CONFIG_SET":         "authio-production-events",
		"AWS_ACCESS_KEY_ID":      exampleKeyID,
		"OK_QUEUE_URL":           "https://sqs.us-east-1.amazonaws.com/123456789012/authio-audit-events-e2e.fifo",
		"OK_BUCKET":              "authio-e2e-branding",
		"OK_STAGING":             "authio-staging-validation-audit-immutable",
		"NODE_ENV":               "production",
		"SENTRY_ENVIRONMENT":     "production",
		"ALERT_WARN_LEVEL":       "production",
		"AUTHIO_PUBLIC_URL":      "https://production.example.com",
		"RAILWAY_SERVICE_NAME":   "authio-production-thing",
		"EMPTY_BUCKET":           "",
	}
	got := findViolations(vars, extra)
	want := []envViolation{
		{"AUDIT_SQS_QUEUE_URL", "production_resource"},
		{"AUTHIO_AWS_SECRET_IDS", "production_resource"},
		{"AUTHIO_BRANDING_BUCKET", "production_resource"},
		{"AUTHIO_KMS_KEY_ID", "production_resource"},
		{"AWS_ACCESS_KEY_ID", "production_credential"},
		{"SES_CONFIG_SET", "production_resource"},
		{"STATUS_SNAPSHOT_URL", "production_resource"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("violation %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestGuardSkipsProductionAndUnknown(t *testing.T) {
	bad := map[string]string{"AUTHIO_BRANDING_BUCKET": "authio-production-branding"}
	for _, tc := range []struct{ railway, authio string }{
		{"production", ""},
		{"production", "e2e"},
		{"", "production"},
		{"", ""},
	} {
		setEnv(t, tc.railway, tc.authio)
		if err := guardEnvironment("config", bad); err != nil {
			t.Fatalf("railway=%q authio=%q: guard ran: %v", tc.railway, tc.authio, err)
		}
	}
}

func TestGuardEnforcesOutsideProduction(t *testing.T) {
	bad := map[string]string{
		"AUTHIO_BRANDING_BUCKET": "authio-production-branding",
		"AWS_ACCESS_KEY_ID":      exampleKeyID,
	}
	for _, tc := range []struct{ railway, authio string }{
		{"e2e", ""},
		{"e2e", "production"}, // a copied AUTHIO_ENV must not disable the guard
		{"", "e2e"},
	} {
		setEnv(t, tc.railway, tc.authio)
		t.Setenv(envGuardDenylistVar, exampleDigest)
		err := guardEnvironment("config", bad)
		if err == nil {
			t.Fatalf("railway=%q authio=%q: guard did not block", tc.railway, tc.authio)
		}
		if strings.Contains(err.Error(), exampleKeyID) || strings.Contains(err.Error(), "authio-production-branding") {
			t.Fatalf("error leaks a value: %v", err)
		}
		if !strings.Contains(err.Error(), "AUTHIO_BRANDING_BUCKET") || !strings.Contains(err.Error(), "AWS_ACCESS_KEY_ID") {
			t.Fatalf("error does not name the variables: %v", err)
		}
	}
}

func TestGuardWarnOnly(t *testing.T) {
	setEnv(t, "e2e", "")
	t.Setenv(envGuardWarnOnlyVar, " AUTHIO_BRANDING_BUCKET ,")
	bad := map[string]string{"AUTHIO_BRANDING_BUCKET": "authio-production-branding"}
	if err := guardEnvironment("config", bad); err != nil {
		t.Fatalf("warn-only var blocked startup: %v", err)
	}
	bad["BACKUP_S3_BUCKET"] = "authio-production-db-backups"
	if err := guardEnvironment("config", bad); err == nil || !strings.Contains(err.Error(), "BACKUP_S3_BUCKET") {
		t.Fatalf("var outside warn list was not enforced: %v", err)
	}
	t.Setenv(envGuardWarnOnlyVar, "*")
	if err := guardEnvironment("config", bad); err == nil {
		t.Fatal("wildcard must not disable the guard")
	}
}
