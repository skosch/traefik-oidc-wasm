package main

import (
	"errors"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Config the plugin configuration.
type Config struct {
	Provider             ProviderConfig    `json:"provider"`
	Cookie               CookieConfig      `json:"cookie"`
	Endpoint             EndpointConfig    `json:"endpoint"`
	TokenAutoRefreshTime time.Duration     `json:"tokenAutoRefreshTime"`
	Totp                 totp.ValidateOpts `json:"totp"`
	DnsAddr              string            `json:"dnsAddr"`
	ClaimMap             map[string]string `json:"claimMap"`
}

type ProviderConfig struct {
	IssuerUrl    string   `json:"issuerUrl"`
	ClientID     string   `json:"clientID"`
	ClientSecret string   `json:"clientSecret"`
	Scopes       []string `json:"scopes"`
}

type CookieConfig struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	OriginPath   string `json:"originPath"`
}

type EndpointConfig struct {
	Callback string `json:"callback"`
	Logout   string `json:"logout"`
	Fallback string `json:"fallback"`
}

func (c *Config) Init() {
	if c.DnsAddr == "" {
		c.DnsAddr = "1.1.1.1:53"
	}
	if c.Endpoint.Callback == "" {
		c.Endpoint.Callback = "/oauth2/callback"
	}
	if c.Endpoint.Fallback == "" {
		c.Endpoint.Fallback = "/"
	}
	if len(c.Provider.Scopes) == 0 {
		c.Provider.Scopes = []string{oidc.ScopeOpenID}
	}
	if c.Cookie.AccessToken == "" {
		c.Cookie.AccessToken = "__oidc_token"
	}
	if c.Cookie.RefreshToken == "" {
		c.Cookie.RefreshToken = "__oidc_refresh_token"
	}
	if c.Cookie.OriginPath == "" {
		c.Cookie.OriginPath = "__oidc_origin_path"
	}
	if c.TokenAutoRefreshTime == 0 {
		c.TokenAutoRefreshTime = time.Minute * 5 // 5 minutes
	}
	if c.Totp.Period == 0 {
		c.Totp.Period = 30
	}
	if c.Totp.Digits == 0 {
		c.Totp.Digits = otp.DigitsEight
	}
	if c.Totp.Algorithm == 0 {
		c.Totp.Algorithm = otp.AlgorithmSHA1
	}
}

func (c *Config) Validate() error {
	if c.Provider.IssuerUrl == "" {
		return errors.New("provider.issuerUrl is required")
	}
	if c.Provider.ClientID == "" {
		return errors.New("provider.clientID is required")
	}
	if c.Provider.ClientSecret == "" {
		return errors.New("provider.clientSecret is required")
	}
	hasOpenID := false
	for _, scope := range c.Provider.Scopes {
		if scope == oidc.ScopeOpenID {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		return errors.New("provider.scopes must include 'openid'")
	}

	return nil
}
