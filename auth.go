package nucleisdk

import (
	"net/url"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	urlutil "github.com/projectdiscovery/utils/url"
)

// AuthType represents the type of authentication.
type AuthType string

const (
	AuthBasic  AuthType = "BasicAuth"
	AuthBearer AuthType = "BearerToken"
	AuthHeader AuthType = "Header"
	AuthCookie AuthType = "Cookie"
	AuthQuery  AuthType = "Query"
)

// AuthConfig represents an authentication configuration for scanning.
type AuthConfig struct {
	Type        AuthType
	Domains     []string
	Username    string
	Password    string
	Token       string
	Headers     map[string]string
	Cookies     map[string]string
	QueryParams map[string]string
}

// BasicAuth creates a basic auth configuration.
func BasicAuth(username, password string, domains ...string) AuthConfig {
	return AuthConfig{
		Type:     AuthBasic,
		Domains:  domains,
		Username: username,
		Password: password,
	}
}

// BearerToken creates a bearer token auth configuration.
func BearerToken(token string, domains ...string) AuthConfig {
	return AuthConfig{
		Type:    AuthBearer,
		Domains: domains,
		Token:   token,
	}
}

// HeaderAuth creates a header-based auth configuration.
func HeaderAuth(headers map[string]string, domains ...string) AuthConfig {
	return AuthConfig{
		Type:    AuthHeader,
		Domains: domains,
		Headers: headers,
	}
}

// CookieAuth creates a cookie-based auth configuration.
func CookieAuth(cookies map[string]string, domains ...string) AuthConfig {
	return AuthConfig{
		Type:    AuthCookie,
		Domains: domains,
		Cookies: cookies,
	}
}

// QueryAuth creates a query parameter auth configuration.
func QueryAuth(params map[string]string, domains ...string) AuthConfig {
	return AuthConfig{
		Type:        AuthQuery,
		Domains:     domains,
		QueryParams: params,
	}
}

// APIKeyHeader is a convenience function for single API key header auth.
func APIKeyHeader(headerName, apiKey string, domains ...string) AuthConfig {
	return HeaderAuth(map[string]string{headerName: apiKey}, domains...)
}

// toSecret converts an AuthConfig to a nuclei authx.Secret.
func (a *AuthConfig) toSecret() authx.Secret {
	secret := authx.Secret{
		Type:    string(a.Type),
		Domains: a.Domains,
	}

	switch a.Type {
	case AuthBasic:
		secret.Username = a.Username
		secret.Password = a.Password
	case AuthBearer:
		secret.Token = a.Token
	case AuthHeader:
		for k, v := range a.Headers {
			secret.Headers = append(secret.Headers, authx.KV{Key: k, Value: v})
		}
	case AuthCookie:
		for k, v := range a.Cookies {
			secret.Cookies = append(secret.Cookies, authx.Cookie{Key: k, Value: v})
		}
	case AuthQuery:
		for k, v := range a.QueryParams {
			secret.Params = append(secret.Params, authx.KV{Key: k, Value: v})
		}
	}

	return secret
}

// sdkAuthProvider implements authprovider.AuthProvider for in-memory auth configs.
type sdkAuthProvider struct {
	secrets []authx.Secret
}

// newSDKAuthProvider creates an auth provider from AuthConfig entries.
// If any config has no domains, targetDomains are used as default.
func newSDKAuthProvider(configs []AuthConfig, targetDomains []string) *sdkAuthProvider {
	var secrets []authx.Secret
	for _, cfg := range configs {
		secret := cfg.toSecret()
		if len(secret.Domains) == 0 && len(targetDomains) > 0 {
			secret.Domains = targetDomains
		}
		secrets = append(secrets, secret)
	}
	return &sdkAuthProvider{secrets: secrets}
}

// LookupAddr looks up a domain/address and returns auth strategies.
func (p *sdkAuthProvider) LookupAddr(addr string) []authx.AuthStrategy {
	host := strings.Split(addr, ":")[0]
	var strategies []authx.AuthStrategy
	for _, secret := range p.secrets {
		if matchesDomain(host, secret.Domains) {
			if strategy := secret.GetStrategy(); strategy != nil {
				strategies = append(strategies, strategy)
			}
		}
	}
	return strategies
}

// LookupURL looks up a URL and returns auth strategies.
func (p *sdkAuthProvider) LookupURL(u *url.URL) []authx.AuthStrategy {
	if u == nil {
		return nil
	}
	return p.LookupAddr(u.Host)
}

// LookupURLX looks up a pd URL and returns auth strategies.
func (p *sdkAuthProvider) LookupURLX(u *urlutil.URL) []authx.AuthStrategy {
	if u == nil {
		return nil
	}
	return p.LookupAddr(u.Host)
}

// GetTemplatePaths returns template paths for dynamic secret fetching.
func (p *sdkAuthProvider) GetTemplatePaths() []string {
	return nil
}

// PreFetchSecrets pre-fetches secrets (no-op for in-memory provider).
func (p *sdkAuthProvider) PreFetchSecrets() error {
	return nil
}

// matchesDomain checks if a host matches any of the given domains.
func matchesDomain(host string, domains []string) bool {
	if len(domains) == 0 {
		return true
	}
	host = strings.ToLower(strings.TrimSpace(host))
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if host == domain {
			return true
		}
		if strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

// extractDomainsFromTargets extracts unique hostnames from target URLs.
func extractDomainsFromTargets(targets []string) []string {
	seen := make(map[string]bool)
	var domains []string
	for _, target := range targets {
		host := target
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			host = u.Hostname()
		}
		host = strings.TrimSpace(host)
		if host != "" && !seen[host] {
			seen[host] = true
			domains = append(domains, host)
		}
	}
	return domains
}
