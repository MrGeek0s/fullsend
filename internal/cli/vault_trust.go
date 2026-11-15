package cli

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/fullsend-ai/fullsend/internal/config"
)

// secretConfigMaxBytes bounds a config file read from the trusted revision.
const secretConfigMaxBytes = 1 << 20

// requireTrustedSecretSources enforces ADR 0155's trusted-revision rule
// before the runner requests a job OIDC token: the merged `connections` and
// `secrets` the run would use must equal what the trusted revision of the
// config directory declares. Any untrusted addition, replacement, removal,
// or native-source reset therefore fails the run, whichever layer carries it.
//
// The trusted revision is read from git objects, never the working tree. For
// an ordinary run it is the checkout's HEAD; for a pull or merge request run
// it is the request's base commit from the event payload, because the
// checkout may be the request's head.
//
// When no trusted revision can be established (the directory is not a git
// checkout, or a request run's base commit is missing), the run fails closed
// if the loaded config declares any connections or secrets. A config that
// declares neither cannot send the OIDC token anywhere, so it passes.
func requireTrustedSecretSources(ctx context.Context, cfg config.ConfigReader, fullsendDir string) error {
	var work secretSourceView
	if reader, ok := cfg.(config.SecretSourcesReader); ok {
		work = viewSecretSources(reader)
	}

	trusted, note, err := loadTrustedSecretSources(ctx, fullsendDir, tirithPolicySourceFromEnv(vaultEnvFn))
	if err != nil {
		return fmt.Errorf("reading the trusted config revision: %w", err)
	}
	if trusted == nil {
		if work.empty() {
			return nil
		}
		return fmt.Errorf("refusing to use connections or secrets from the loaded config: %s", note)
	}
	if !reflect.DeepEqual(work, *trusted) {
		return fmt.Errorf("the loaded config's connections and secrets differ from the trusted revision of %s; "+
			"Vault connection and secret selections may be added, changed, or removed only in a trusted revision (ADR 0155)", fullsendDir)
	}
	return nil
}

// secretSourceView is the comparable form of the merged connections and
// secrets. Empty maps are normalized to nil.
type secretSourceView struct {
	Connections map[string]config.SecretConnection
	Secrets     map[string]config.SecretSource
}

func (v secretSourceView) empty() bool {
	return len(v.Connections) == 0 && len(v.Secrets) == 0
}

func viewSecretSources(r config.SecretSourcesReader) secretSourceView {
	var v secretSourceView
	if conns := r.ConfigConnections(); len(conns) > 0 {
		v.Connections = conns
	}
	if secrets := r.ConfigSecrets(); len(secrets) > 0 {
		v.Secrets = secrets
	}
	return v
}

// loadTrustedSecretSources returns the merged connections and secrets
// declared by the trusted revision of the config directory. It returns nil
// and a reason when no trusted revision is available.
func loadTrustedSecretSources(ctx context.Context, dir string, src tirithPolicySource) (*secretSourceView, string, error) {
	topOut, err := runGit(ctx, dir, "rev-parse", "--show-toplevel")
	if err != nil || strings.TrimSpace(string(topOut)) == "" {
		return nil, "the config directory is not a git checkout, so no trusted revision is available", nil
	}
	rev := "HEAD"
	if src.requestRun {
		base := strings.ToLower(strings.TrimSpace(src.baseSHA))
		if !gitObjectIDPattern.MatchString(base) || !gitCommitExists(ctx, dir, base) {
			return nil, "this is a pull or merge request run and its base commit is not available in the config checkout (the head copy is never trusted)", nil
		}
		rev = base
	} else if !gitCommitExists(ctx, dir, rev) {
		return nil, "the config checkout has no commits, so no trusted revision is available", nil
	}

	tmp, err := os.MkdirTemp("", "fullsend-trusted-config-")
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	for _, name := range []string{config.OverlayConfigFile, config.BaseConfigFile} {
		data, found, err := gitBlobAt(ctx, dir, rev, name)
		if err != nil {
			return nil, "", err
		}
		if !found {
			continue
		}
		if err := os.WriteFile(tmp+"/"+name, data, 0o600); err != nil {
			return nil, "", err
		}
	}
	cfg, err := config.LoadConfigWriter(tmp, config.LoadOpts{MissingOK: true})
	if err != nil {
		return nil, "", fmt.Errorf("loading the config at %s: %w", shortRev(rev), err)
	}
	reader, ok := cfg.(config.SecretSourcesReader)
	if !ok {
		return nil, "", fmt.Errorf("the config at %s does not expose secret sources", shortRev(rev))
	}
	view := viewSecretSources(reader)
	return &view, "", nil
}

// gitBlobAt reads the regular file at relPath in rev. A missing path reports
// found=false. A symlink, submodule, or oversized file is an error.
func gitBlobAt(ctx context.Context, dir, rev, relPath string) ([]byte, bool, error) {
	out, err := runGit(ctx, dir, "ls-tree", "-z", rev, "--", relPath)
	if err != nil {
		return nil, false, fmt.Errorf("listing %s at %s: %w", relPath, shortRev(rev), err)
	}
	entry := strings.TrimSuffix(string(out), "\x00")
	if entry == "" {
		return nil, false, nil
	}
	meta, _, ok := strings.Cut(entry, "\t")
	fields := strings.Fields(meta)
	if !ok || len(fields) != 3 {
		return nil, false, fmt.Errorf("unexpected git ls-tree output for %s at %s", relPath, shortRev(rev))
	}
	mode, kind, oid := fields[0], fields[1], fields[2]
	if kind != "blob" || (mode != "100644" && mode != "100755") {
		return nil, false, fmt.Errorf("%s at %s is not a regular file (mode %s, %s)", relPath, shortRev(rev), mode, kind)
	}
	if !gitObjectIDPattern.MatchString(oid) {
		return nil, false, fmt.Errorf("unexpected object name for %s at %s", relPath, shortRev(rev))
	}
	sizeOut, err := runGit(ctx, dir, "cat-file", "-s", oid)
	if err != nil {
		return nil, false, fmt.Errorf("sizing %s at %s: %w", relPath, shortRev(rev), err)
	}
	size, err := strconv.ParseInt(strings.TrimSpace(string(sizeOut)), 10, 64)
	if err != nil {
		return nil, false, fmt.Errorf("sizing %s at %s: %w", relPath, shortRev(rev), err)
	}
	if size > secretConfigMaxBytes {
		return nil, false, fmt.Errorf("%s at %s is %d bytes, over the %d-byte limit", relPath, shortRev(rev), size, secretConfigMaxBytes)
	}
	data, err := runGit(ctx, dir, "cat-file", "blob", oid)
	if err != nil {
		return nil, false, fmt.Errorf("reading %s at %s: %w", relPath, shortRev(rev), err)
	}
	return data, true, nil
}
