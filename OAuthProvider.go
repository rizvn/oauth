package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/rizvn/panics"
)

type OAuthProvider struct {
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	JwksUri                     string `json:"jwks_uri"`

	jwks       map[string]jose.JSONWebKey
	httpClient *http.Client
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

func (r *OAuthProvider) Init(discoveryUrl string) {
	resp, err := http.Get(discoveryUrl)
	panics.OnError(err, "failed to fetch OIDC oauthProvider document")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	panics.OnError(err, "failed to read OIDC oauthProvider document")

	err = json.Unmarshal(body, r)
	panics.OnError(err, "failed to unmarshal OIDC oauthProvider document")

	// Fetch JWKS
	jwks, err := r.fetchJwks()
	panics.OnError(err, "failed to fetch JWKS from provider")

	r.jwks = jwks
	r.httpClient = &http.Client{}
}

func (r *OAuthProvider) GetKey(kid string) jose.JSONWebKey {
	jwk, ok := r.jwks[kid]
	if !ok {
		// Try to refresh JWKS
		jwks, err := r.fetchJwks()
		panics.OnError(err, "failed to fetch JWKS from provider")

		// Update local jwks
		r.jwks = jwks

		// Try to get the key again
		jwk, ok = r.jwks[kid]
		panics.OnFalse(ok, fmt.Sprintf("JWK with kid %s not found in provider JWKS after refresh", kid))
	}
	return jwk
}

func (r *OAuthProvider) fetchJwks() (map[string]jose.JSONWebKey, error) {
	resp, err := http.Get(r.JwksUri)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jwks jose.JSONWebKeySet
	err = json.Unmarshal(body, &jwks)
	if err != nil {
		return nil, err
	}

	keyMap := make(map[string]jose.JSONWebKey)
	for _, key := range jwks.Keys {
		keyMap[key.KeyID] = key
	}
	return keyMap, nil
}

func (r *OAuthProvider) ExchangeCodeForToken(code, clientId, clientSecret, redirectUrl string) *TokenResponse {
	tokenEndpoint := r.TokenEndpoint

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", clientId)
	data.Set("client_secret", clientSecret)
	data.Set("redirect_uri", redirectUrl)

	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(data.Encode()))
	panics.OnError(err, "failed to create token exchange request")

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := r.httpClient.Do(req)
	panics.OnError(err, "failed to execute token exchange request")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	panics.OnError(err, "failed to read token exchange response body")

	if resp.StatusCode != http.StatusOK {
		panics.OnError(fmt.Errorf("ExchangeCodeForToken failed"), "")
	}

	var tokenResp TokenResponse
	err = json.Unmarshal(body, &tokenResp)
	panics.OnError(err, "failed to unmarshal token exchange response")
	return &tokenResp
}

func (r *OAuthProvider) ExchangeRefreshTokenForNewTokens(refreshToken, clientId, clientSecret string) *TokenResponse {
	tokenEndpoint := r.TokenEndpoint

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", clientId)
	data.Set("client_secret", clientSecret)
	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(data.Encode()))
	panics.OnError(err, "failed to create token refresh request")

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := r.httpClient.Do(req)
	panics.OnError(err, "failed to execute token refresh request")

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	panics.OnError(err, "failed to read token refresh response body")

	if resp.StatusCode != http.StatusOK {
		panics.OnError(fmt.Errorf("token refresh failed"), "")
	}

	var tokenResp TokenResponse
	err = json.Unmarshal(body, &tokenResp)
	panics.OnError(err, "failed to unmarshal token refresh response")
	return &tokenResp
}
