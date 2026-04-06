package repos

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Repo represents a registered policy repository.
type Repo struct {
	URL       string `json:"url"`
	LocalPath string `json:"local_path"`
}

// Config holds all registered repositories.
type Config struct {
	Repos []Repo `json:"repos"`
}

func configPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolving config directory: %w", err)
	}
	return filepath.Join(dir, "oy", "config.json"), nil
}

func cacheBase() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolving cache directory: %w", err)
	}
	return filepath.Join(dir, "oy", "repos"), nil
}

// Load reads the persisted config from disk. Returns an empty config if none exists yet.
func Load() (*Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %q: %w", path, err)
	}
	return &cfg, nil
}

func save(cfg *Config) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// NormalizeURL converts a bare host/path reference to a clonable HTTPS URL.
// e.g. "github.com/aljoshare/oy-policies" → "https://github.com/aljoshare/oy-policies"
func NormalizeURL(raw string) string {
	if strings.HasPrefix(raw, "https://") ||
		strings.HasPrefix(raw, "http://") ||
		strings.HasPrefix(raw, "git@") ||
		strings.HasPrefix(raw, "ssh://") {
		return raw
	}
	return "https://" + raw
}

// localDirName converts a clone URL to a safe directory name.
func localDirName(cloneURL string) string {
	name := strings.TrimPrefix(cloneURL, "https://")
	name = strings.TrimPrefix(name, "http://")
	name = strings.TrimSuffix(name, ".git")
	r := strings.NewReplacer("/", "_", ":", "_", "@", "_")
	return r.Replace(name)
}

// Add registers a policy repository, cloning it into the local cache.
// rawURL may be a bare host/path (e.g. "github.com/owner/repo") or a full URL.
func Add(rawURL string) (*Repo, error) {
	cloneURL := NormalizeURL(rawURL)

	cfg, err := Load()
	if err != nil {
		return nil, err
	}
	for _, r := range cfg.Repos {
		if r.URL == rawURL {
			return nil, fmt.Errorf("repository %q is already registered (local path: %s)", rawURL, r.LocalPath)
		}
	}

	base, err := cacheBase()
	if err != nil {
		return nil, err
	}
	localPath := filepath.Join(base, localDirName(cloneURL))

	if err := os.MkdirAll(base, 0o755); err != nil {
		return nil, fmt.Errorf("creating cache directory: %w", err)
	}

	if _, err := os.Stat(localPath); err == nil {
		// Directory already exists — pull latest changes.
		cmd := exec.Command("git", "-C", localPath, "pull", "--ff-only")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("updating repository: %w", err)
		}
	} else {
		cmd := exec.Command("git", "clone", "--depth=1", cloneURL, localPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("cloning %q: %w", cloneURL, err)
		}
	}

	repo := Repo{URL: rawURL, LocalPath: localPath}
	cfg.Repos = append(cfg.Repos, repo)
	if err := save(cfg); err != nil {
		return nil, err
	}
	return &repo, nil
}

// LocalPaths returns the local filesystem paths of all registered repositories.
func (c *Config) LocalPaths() []string {
	paths := make([]string, len(c.Repos))
	for i, r := range c.Repos {
		paths[i] = r.LocalPath
	}
	return paths
}
