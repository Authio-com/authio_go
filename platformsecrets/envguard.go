package platformsecrets

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Environment isolation guard (AUT-93).
//
// Outside production, a service must not be configured with a production
// AWS resource or a production credential. Bootstrap runs this check before
// fetching any secret and again over the values it loaded, and refuses to
// start on a match. In production the check is skipped entirely.
//
// The environment comes from RAILWAY_ENVIRONMENT_NAME, which the platform
// injects and which cannot be copied between environments, then AUTHIO_ENV.
// When neither is set (local dev) the check is skipped.
//
// AUTHIO_ENV_GUARD_WARN_ONLY lists variable names (comma separated, no
// wildcards) whose matches are logged but do not block startup; use it only
// while a known issue is being fixed. AUTHIO_ENV_GUARD_DENYLIST adds
// denylist hashes (same format as denylist.go).
//
// Logs carry variable names and the rule that matched, never values.

const (
	envGuardWarnOnlyVar = "AUTHIO_ENV_GUARD_WARN_ONLY"
	envGuardDenylistVar = "AUTHIO_ENV_GUARD_DENYLIST"
	denylistHashPrefix  = "authio-env-guard/v1\n"
)

var (
	productionMarker = regexp.MustCompile(`(?i)(^|[^a-z0-9])production([^a-z0-9]|$)`)
	awsResourceName  = regexp.MustCompile(`(?i)(SQS|QUEUE|BUCKET|KMS|(^|_)ARN(_|$)|CONFIG_SET|CONFIGURATION_SET|SNS|TOPIC|SECRET_IDS)`)
	awsResourceValue = regexp.MustCompile(`(?i)^arn:aws[a-z-]*:|^s3://|^https://sqs\.|\.s3[.-]([a-z0-9-]+\.)*amazonaws\.com|//s3[.-]([a-z0-9-]+\.)*amazonaws\.com/`)
)

type envViolation struct {
	Name string
	Rule string
}

// environmentName returns the deployment environment and whether the guard
// applies to it.
func environmentName() (string, bool) {
	railway := strings.ToLower(strings.TrimSpace(os.Getenv("RAILWAY_ENVIRONMENT_NAME")))
	authio := strings.ToLower(strings.TrimSpace(os.Getenv("AUTHIO_ENV")))
	name := railway
	if name == "" {
		name = authio
	}
	if name == "" || name == "production" {
		return name, false
	}
	if railway != "" && authio == "production" {
		slog.Warn("platformsecrets.env_guard_env_mismatch",
			"railway_environment", railway,
			"authio_env", authio,
		)
	}
	return name, true
}

func denylistDigest(value string) string {
	sum := sha256.Sum256([]byte(denylistHashPrefix + value))
	return hex.EncodeToString(sum[:])
}

func splitList(raw string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out[p] = struct{}{}
		}
	}
	return out
}

// findViolations inspects vars and returns matches sorted by name.
func findViolations(vars map[string]string, extraDenylist map[string]struct{}) []envViolation {
	var out []envViolation
	for name, value := range vars {
		if value == "" || strings.HasPrefix(name, "RAILWAY_") ||
			name == envGuardWarnOnlyVar || name == envGuardDenylistVar {
			continue
		}
		if (awsResourceName.MatchString(name) || awsResourceValue.MatchString(value)) &&
			productionMarker.MatchString(value) {
			out = append(out, envViolation{Name: name, Rule: "production_resource"})
			continue
		}
		d := denylistDigest(strings.TrimSpace(value))
		_, denied := productionDenylist[d]
		if !denied {
			_, denied = extraDenylist[d]
		}
		if denied {
			out = append(out, envViolation{Name: name, Rule: "production_credential"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// guardEnvironment returns an error when vars hold an enforced violation.
// stage names the pass ("config" or "secrets") in logs.
func guardEnvironment(stage string, vars map[string]string) error {
	envName, applies := environmentName()
	if !applies {
		return nil
	}
	warnOnly := splitList(os.Getenv(envGuardWarnOnlyVar))
	violations := findViolations(vars, splitList(os.Getenv(envGuardDenylistVar)))

	var blocked []string
	for _, v := range violations {
		_, warn := warnOnly[v.Name]
		mode := "enforce"
		if warn {
			mode = "warn"
		} else {
			blocked = append(blocked, v.Name)
		}
		slog.Error("platformsecrets.env_guard_violation",
			"environment", envName,
			"stage", stage,
			"var", v.Name,
			"rule", v.Rule,
			"mode", mode,
		)
	}
	if len(blocked) > 0 {
		return fmt.Errorf("platformsecrets: refusing to start in %q: production-scoped values in %s",
			envName, strings.Join(blocked, ", "))
	}
	slog.Info("platformsecrets.env_guard_ok",
		"environment", envName,
		"stage", stage,
		"vars_checked", len(vars),
		"warnings", len(violations),
	)
	return nil
}

func processEnv() map[string]string {
	out := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			out[k] = v
		}
	}
	return out
}
