// Package platformsecrets hydrates process environment from AWS Secrets
// Manager before config parsing. Railway keeps bootstrap creds
// (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, DATABASE_URL) and
// AUTHIO_AWS_SECRET_IDS; everything else can live in SM.
package platformsecrets

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// Bootstrap loads each secret ID listed in AUTHIO_AWS_SECRET_IDS. Values
// must be JSON objects mapping env var names to strings. Existing env vars
// are never overwritten so local dev overrides keep working.
func Bootstrap(ctx context.Context) error {
	ids := parseIDs(os.Getenv("AUTHIO_AWS_SECRET_IDS"))
	if len(ids) == 0 {
		return nil
	}

	region := strings.TrimSpace(os.Getenv("AWS_REGION"))
	if region == "" {
		region = strings.TrimSpace(os.Getenv("AWS_DEFAULT_REGION"))
	}
	if region == "" {
		region = "us-east-1"
	}

	loadCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(loadCtx, config.WithRegion(region))
	if err != nil {
		return fmt.Errorf("platformsecrets aws config: %w", err)
	}
	sm := secretsmanager.NewFromConfig(cfg)

	var loaded int
	for _, id := range ids {
		n, err := mergeSecret(loadCtx, sm, id)
		if err != nil {
			return err
		}
		loaded += n
	}

	slog.Info("platformsecrets.bootstrap_ok",
		"secret_count", len(ids),
		"env_keys_loaded", loaded,
	)
	return nil
}

func parseIDs(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func mergeSecret(ctx context.Context, sm *secretsmanager.Client, id string) (int, error) {
	out, err := sm.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(id),
	})
	if err != nil {
		return 0, fmt.Errorf("platformsecrets get %q: %w", id, err)
	}
	if out.SecretString == nil || strings.TrimSpace(*out.SecretString) == "" {
		return 0, fmt.Errorf("platformsecrets get %q: empty secret", id)
	}

	var kv map[string]string
	if err := json.Unmarshal([]byte(*out.SecretString), &kv); err != nil {
		return 0, fmt.Errorf("platformsecrets decode %q: %w", id, err)
	}

	n := 0
	for k, v := range kv {
		if k == "" || v == "" {
			continue
		}
		if cur := os.Getenv(k); cur != "" {
			continue
		}
		if err := os.Setenv(k, v); err != nil {
			return n, fmt.Errorf("platformsecrets setenv %q: %w", k, err)
		}
		n++
	}
	return n, nil
}
