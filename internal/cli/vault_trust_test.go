package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fullsend-ai/fullsend/internal/config"
)

func gitInDir(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir,
		"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// trustedConfigCheckout commits trustedYAML as .fullsend/config.yaml, then
// overwrites the working tree copy with workYAML (empty keeps it, "-"
// deletes it). It returns the .fullsend directory and the commit SHA.
func trustedConfigCheckout(t *testing.T, trustedYAML, workYAML string) (string, string) {
	t.Helper()
	repo := t.TempDir()
	dir := filepath.Join(repo, ".fullsend")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	gitInDir(t, repo, "init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(trustedYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	gitInDir(t, repo, "add", ".fullsend/config.yaml")
	gitInDir(t, repo, "commit", "-q", "-m", "trusted")
	sha := gitInDir(t, repo, "rev-parse", "HEAD")
	switch workYAML {
	case "":
	case "-":
		if err := os.Remove(filepath.Join(dir, "config.yaml")); err != nil {
			t.Fatal(err)
		}
	default:
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(workYAML), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, sha
}

func loadWorkingConfig(t *testing.T, dir string) config.ConfigReader {
	t.Helper()
	cfg, err := config.LoadConfig(dir, config.LoadOpts{MissingOK: true})
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return cfg
}

func TestRequireTrustedSecretSources(t *testing.T) {
	trusted := vaultConfigYAML("https://vault.example.com")
	replacedAddr := vaultConfigYAML("https://attacker.example.net")
	replacedPaths := strings.Replace(trusted, "kv/data/fullsend/otel", "kv/data/attacker/otel", 1)
	nativeReset := strings.Replace(trusted, "  OTEL_EXPORTER_OTLP_TRACES_HEADERS:\n    connection: corp\n    vault_secrets: [kv/data/fullsend/otel]\n",
		"  OTEL_EXPORTER_OTLP_TRACES_HEADERS:\n    connection: native\n", 1)
	omittedConnection := strings.Replace(trusted, "  OTEL_EXPORTER_OTLP_TRACES_HEADERS:\n    connection: corp\n    vault_secrets: [kv/data/fullsend/otel]\n",
		"  OTEL_EXPORTER_OTLP_TRACES_HEADERS: {}\n", 1)
	if nativeReset == trusted || omittedConnection == trusted {
		t.Fatal("test fixture did not change the config")
	}

	tests := []struct {
		name    string
		trusted string
		work    string // "" = unchanged, "-" = removed
		wantErr string
	}{
		{name: "unchanged", trusted: trusted},
		{name: "address replaced", trusted: trusted, work: replacedAddr, wantErr: "differ from the trusted revision"},
		{name: "paths replaced", trusted: trusted, work: replacedPaths, wantErr: "differ from the trusted revision"},
		{name: "native reset", trusted: trusted, work: nativeReset, wantErr: "differ from the trusted revision"},
		{name: "connection omitted", trusted: trusted, work: omittedConnection, wantErr: "differ from the trusted revision"},
		{name: "selection added", trusted: "version: \"1\"\n", work: trusted, wantErr: "differ from the trusted revision"},
		{name: "selection removed", trusted: trusted, work: "version: \"1\"\n", wantErr: "differ from the trusted revision"},
		{name: "config removed", trusted: trusted, work: "-", wantErr: "differ from the trusted revision"},
		{name: "no sources anywhere", trusted: "version: \"1\"\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withVaultEnv(t, map[string]string{})
			dir, _ := trustedConfigCheckout(t, tt.trusted, tt.work)
			err := requireTrustedSecretSources(context.Background(), loadWorkingConfig(t, dir), dir)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
			// The error never quotes configured addresses or paths.
			if strings.Contains(err.Error(), "attacker") {
				t.Fatalf("error leaks config content: %v", err)
			}
		})
	}
}

func TestRequireTrustedSecretSources_NotAGitCheckout(t *testing.T) {
	withVaultEnv(t, map[string]string{})
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(vaultConfigYAML("https://vault.example.com")), 0o600); err != nil {
		t.Fatal(err)
	}
	err := requireTrustedSecretSources(context.Background(), loadWorkingConfig(t, dir), dir)
	if err == nil || !strings.Contains(err.Error(), "not a git checkout") {
		t.Fatalf("error = %v, want not-a-git-checkout refusal", err)
	}

	// A config with no connections or secrets cannot send the token anywhere.
	empty := t.TempDir()
	if err := os.WriteFile(filepath.Join(empty, "config.yaml"), []byte("version: \"1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := requireTrustedSecretSources(context.Background(), loadWorkingConfig(t, empty), empty); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := requireTrustedSecretSources(context.Background(), nil, empty); err != nil {
		t.Fatalf("nil config: unexpected error: %v", err)
	}
}

func TestRequireTrustedSecretSources_RequestRunUsesBaseCommit(t *testing.T) {
	trusted := vaultConfigYAML("https://vault.example.com")
	repo := t.TempDir()
	dir := filepath.Join(repo, ".fullsend")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	gitInDir(t, repo, "init", "-q")
	write := func(yaml string) {
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		gitInDir(t, repo, "add", ".fullsend/config.yaml")
		gitInDir(t, repo, "commit", "-q", "-m", "c")
	}
	write(trusted)
	base := gitInDir(t, repo, "rev-parse", "HEAD")
	// The PR head commits an attacker address; HEAD is the head checkout.
	write(vaultConfigYAML("https://attacker.example.net"))

	event := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(event, []byte(`{"pull_request":{"base":{"sha":"`+base+`"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	withVaultEnv(t, map[string]string{"GITHUB_EVENT_PATH": event})
	err := requireTrustedSecretSources(context.Background(), loadWorkingConfig(t, dir), dir)
	if err == nil || !strings.Contains(err.Error(), "differ from the trusted revision") {
		t.Fatalf("head config must differ from the base commit, got %v", err)
	}

	// Unchanged against the base commit passes.
	gitInDir(t, repo, "checkout", "-q", base, "--", ".fullsend/config.yaml")
	if err := requireTrustedSecretSources(context.Background(), loadWorkingConfig(t, dir), dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A request run whose base commit is missing fails closed when the
	// config declares sources.
	bogus := strings.Repeat("a", 40)
	if err := os.WriteFile(event, []byte(`{"pull_request":{"base":{"sha":"`+bogus+`"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err = requireTrustedSecretSources(context.Background(), loadWorkingConfig(t, dir), dir)
	if err == nil || !strings.Contains(err.Error(), "base commit is not available") {
		t.Fatalf("error = %v, want missing-base refusal", err)
	}
}

// A GitHub issue_comment run on a pull request carries PR_NUMBER but no base
// commit in its payload; its checkout is the default branch tip, so an
// unchanged config passes and a changed one is still refused.
func TestRequireTrustedSecretSources_IssueCommentRunUsesHead(t *testing.T) {
	trusted := vaultConfigYAML("https://vault.example.com")
	env := map[string]string{"GITHUB_EVENT_NAME": "issue_comment", "PR_NUMBER": "7"}

	withVaultEnv(t, env)
	dir, _ := trustedConfigCheckout(t, trusted, "")
	if err := requireTrustedSecretSources(context.Background(), loadWorkingConfig(t, dir), dir); err != nil {
		t.Fatalf("unchanged config on an issue_comment run: %v", err)
	}

	dir, _ = trustedConfigCheckout(t, trusted, vaultConfigYAML("https://attacker.example.net"))
	err := requireTrustedSecretSources(context.Background(), loadWorkingConfig(t, dir), dir)
	if err == nil || !strings.Contains(err.Error(), "differ from the trusted revision") {
		t.Fatalf("error = %v, want override refusal", err)
	}
}

// A pull or merge request event is recognized from the event name alone, so
// an unreadable event file cannot turn the request checkout into the trusted
// revision.
func TestRequireTrustedSecretSources_RequestEventWithoutBaseFailsClosed(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	for name, env := range map[string]map[string]string{
		"pull_request":        {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": missing},
		"pull_request_target": {"GITHUB_EVENT_NAME": "pull_request_target"},
		"merge request":       {"CI_PIPELINE_SOURCE": "merge_request_event"},
	} {
		t.Run(name, func(t *testing.T) {
			withVaultEnv(t, env)
			dir, _ := trustedConfigCheckout(t, vaultConfigYAML("https://vault.example.com"), "")
			err := requireTrustedSecretSources(context.Background(), loadWorkingConfig(t, dir), dir)
			if err == nil || !strings.Contains(err.Error(), "base commit is not available") {
				t.Fatalf("error = %v, want missing-base refusal", err)
			}
		})
	}
}

// The guard refuses an untrusted override on its own, before the resolver
// (the only code that requests an OIDC token) runs, so Vault sees no login.
func TestRequireTrustedSecretSources_OverrideReachesNoVault(t *testing.T) {
	fake := &cliFakeVault{secrets: map[string]map[string]any{}}
	addr := fake.start(t)
	withVaultEnv(t, map[string]string{})

	dir, _ := trustedConfigCheckout(t, vaultConfigYAML("https://vault.example.com"), vaultConfigYAML(addr))
	if err := requireTrustedSecretSources(context.Background(), loadWorkingConfig(t, dir), dir); err == nil {
		t.Fatal("expected the override to be refused")
	}
	if fake.logins != 0 {
		t.Fatalf("Vault received %d login request(s) for an untrusted override", fake.logins)
	}
}
