package main

import (
	"errors"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type StringBoolean bool

// Config the plugin configuration.
type Config struct {
	Enable               StringBoolean     `json:"enable"`
	Provider             ProviderConfig    `json:"provider"`
	Cookie               CookieConfig      `json:"cookie"`
	Endpoint             EndpointConfig    `json:"endpoint"`
	TokenAutoRefreshTime time.Duration     `json:"tokenAutoRefreshTime"`
	Totp                 totp.ValidateOpts `json:"totp"`
	DNSAddr              string            `json:"dnsAddr"`
	ClaimMap             map[string]string `json:"claimMap"`
}

type ProviderConfig struct {
	IssuerURL    string   `json:"issuerUrl"`
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

func NewConfig() *Config {
	return &Config{
		Enable: true,
		Provider: ProviderConfig{
			Scopes: []string{oidc.ScopeOpenID},
		},
		Cookie: CookieConfig{
			AccessToken:  "__oidc_token",
			RefreshToken: "__oidc_refresh_token",
			OriginPath:   "__oidc_origin_path",
		},
		Endpoint: EndpointConfig{
			Callback: "/oauth2/callback",
			Fallback: "/",
		},
		Totp: totp.ValidateOpts{
			Period:    30, //nolint:mnd
			Digits:    otp.DigitsEight,
			Algorithm: otp.AlgorithmSHA1,
		},
		DNSAddr:              "1.1.1.1:53",
		TokenAutoRefreshTime: time.Minute * 5, //nolint:mnd
	}
}

func (c *Config) Validate() error {
	if c.Provider.IssuerURL == "" {
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

func (b *StringBoolean) UnmarshalJSON(data []byte) error {
	switch string(data) {
	case "true":
		*b = true
	case "false":
		*b = false
	case `"true"`:
		*b = true
	case `"false"`:
		*b = false
	default:
		return errors.New("invalid boolean value")
	}
	return nil
}
