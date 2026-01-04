package oauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	uuid2 "github.com/google/uuid"
	"github.com/rizvn/oauth/kvstore"
	"github.com/rizvn/oauth/locker"
	"github.com/rizvn/oauth/rolemapping"
	"github.com/rizvn/panics"
)

type OAuthRequestInterceptor struct {
	// Configuration fields
	JwtCookieName            string
	PostLoginUrlCookieName   string
	PostLoginPath            string
	DiscoveryUrl             string
	RedirectUrl              string
	ClientId                 string
	ClientSecret             string
	RefreshExpiredTokensStr  string
	ExcludePaths             string
	SecureCookiesStr         string
	WebAppBaseUrl            string
	EncryptAccessTokenCookie bool
	EncryptionPublicKeyPath  string
	EncryptionPrivateKeyPath string
	UsernameClaim            string

	// Configurable interfaces
	KVStore    kvstore.KVStore
	Locker     locker.Locker
	RoleMapper rolemapping.RoleMapper

	// Internal fields
	secureCookies        bool
	refreshExpiredTokens bool
	oauthProvider        *OAuthProvider
	jweEncryptor         *JweEncryptor
	cookieManager        *CookieManager
}

const REFRESH_TOKEN_PREFIX = "reftoken:"
const REFRESH_RESPONSE_PREFIX = "refresh_response:"
const OIDC_STATE_PREFIX = "oidc_state:"

func (r *OAuthRequestInterceptor) Init() {
	if r.JwtCookieName == "" {
		r.JwtCookieName = "oidc_jwt"
	}

	if r.PostLoginUrlCookieName == "" {
		r.PostLoginUrlCookieName = "oidc_redirect_url"
	}

	if r.PostLoginPath == "" {
		r.PostLoginPath = "/"
	}

	if r.RefreshExpiredTokensStr == "" {
		// default to true if not set
		r.refreshExpiredTokens = true
	} else if strings.ToLower(strings.TrimSpace(r.RefreshExpiredTokensStr)) == "true" {
		r.refreshExpiredTokens = true
	}

	if r.SecureCookiesStr == "" {
		// default to true if not set
		r.secureCookies = true
	} else if strings.ToLower(strings.TrimSpace(r.SecureCookiesStr)) == "true" {
		r.refreshExpiredTokens = true
	}

	if r.UsernameClaim == "" {
		r.UsernameClaim = "preferred_username"
	}

	if r.EncryptAccessTokenCookie {
		r.jweEncryptor = &JweEncryptor{}
		r.jweEncryptor.PublicKeyPath = r.EncryptionPublicKeyPath
		r.jweEncryptor.PrivateKeyPath = r.EncryptionPrivateKeyPath
		r.jweEncryptor.Init()
	}

	// init structs
	r.oauthProvider = &OAuthProvider{}
	r.oauthProvider.Init(r.DiscoveryUrl)

	// set in memory kv store if not provided
	if r.KVStore == nil {
		r.KVStore = &kvstore.InMemKVStore{}
		r.KVStore.Init()
	}

	// init Locker for critical sections
	if r.Locker == nil {
		r.Locker = &locker.InMemLocker{}
		r.Locker.Init()
	}

	// init role mapper
	if r.RoleMapper == nil {
		roleMapper := &rolemapping.NoopRoleMapper{}
		r.RoleMapper = roleMapper
		r.RoleMapper.Init()
	}

	r.cookieManager = &CookieManager{
		SecureCookies: r.secureCookies,
	}
	r.cookieManager.Init()
}

func (r *OAuthRequestInterceptor) Interceptor(next http.Handler) http.Handler {
	// return a handler function
	return http.HandlerFunc(func(w http.ResponseWriter, rq *http.Request) {

		// Skip excluded paths
		excludedPaths := strings.Split(r.ExcludePaths, ",")
		for _, path := range excludedPaths {
			if strings.TrimSpace(path) == rq.URL.Path {
				next.ServeHTTP(w, rq)
				return
			}
		}

		// Handle logout endpoint
		if rq.URL.Path == "/oidc/logout" {
			r.deleteOidcCookies(w)
			next.ServeHTTP(w, rq)
			return
		}

		// Handle OIDC redirect endpoint
		if rq.URL.Path == "/oidc/redirect" {
			r.handleOidcRedirect(w, rq)
			return
		}

		// Check for token in header or cookie
		token := r.getTokenFromCookie(rq)
		tokenInCookie := false

		if token != "" {
			tokenInCookie = true
			if r.EncryptAccessTokenCookie {
				token = r.jweEncryptor.Decrypt(token)
			}
		}

		if !tokenInCookie {
			token = r.getTokenFromHeader(rq)
		}

		if token == "" {
			// No token found, redirect to IDP
			r.redirectToIdp(w, rq)
			return
		}

		// Validate the token
		decodedToken, err := r.validateAccessToken(token)

		// Handle token validation errors
		if err != nil {
			//if error is not token expired, return unauthorized
			if !strings.Contains(err.Error(), "token is expired") {
				r.deleteOidcCookies(w)
				http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
				return
			}

			if tokenInCookie {
				var newToken *jwt.Token

				if r.refreshExpiredTokens {
					newToken = r.refreshExpiredToken(decodedToken, w)
				}

				if newToken == nil {
					r.deleteOidcCookies(w)
					r.redirectToIdp(w, rq)
					return
				}
				decodedToken = newToken
			} else {
				// For header token, return unauthorized
				http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
				return
			}
		}

		rq, err = r.createUserFromToken(decodedToken, rq)

		if err != nil {
			http.Error(w, "Failed to create user from token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Handle OIDC status endpoint
		if rq.URL.Path == "/oidc/whoami" {
			w.Header().Set("Content-Type", "application/json")
			claims, ok := decodedToken.Claims.(jwt.MapClaims)
			panics.OnFalse(ok, "failed to decode access token")
			w.WriteHeader(http.StatusOK)
			toJson(w, claims)
			return
		}

		// Call the next handler with the updated request
		next.ServeHTTP(w, rq)
	})
}

func (r *OAuthRequestInterceptor) createUserFromToken(decodedToken *jwt.Token, rq *http.Request) (*http.Request, error) {
	decodeClaims, ok := decodedToken.Claims.(jwt.MapClaims)
	panics.OnFalse(ok, "failed to decoded access token claims")

	username := decodeClaims[r.UsernameClaim].(string)

	userInfo := make(map[string]any)
	userInfo["username"] = username
	userInfo["userRoles"] = r.RoleMapper.GetRoles(username, decodedToken)

	newCtx := context.WithValue(rq.Context(), "userInfo", userInfo)
	newRq := rq.WithContext(newCtx)
	return newRq, nil
}

/**
 * refreshExpiredToken - refreshes the access token using the refresh token
 * returns the new access token, or blank string if refresh failed
 */
func (r *OAuthRequestInterceptor) refreshExpiredToken(decodedToken *jwt.Token, w http.ResponseWriter) *jwt.Token {
	claims, ok := decodedToken.Claims.(jwt.MapClaims)
	panics.OnFalse(ok, "failed to decode access token claims")

	accessTokenId, ok := claims["jti"].(string)

	if !ok || accessTokenId == "" {
		slog.Error("access token does not have accessTokenId claim")
		return nil
	}

	//=== Critical section starts ===
	r.Locker.Lock(accessTokenId)
	tokenResponse := &TokenResponse{}
	cachedTokenResponse := r.KVStore.Get(REFRESH_RESPONSE_PREFIX + accessTokenId)
	if cachedTokenResponse != "" {
		err := json.Unmarshal([]byte(cachedTokenResponse), tokenResponse)
		panics.OnError(err, "failed to unmarshal token refresh response")
	} else {
		refreshToken, err := r.fetchRefreshToken(accessTokenId)
		if err != nil {
			slog.Error("failed to fetch refresh token: %v", err)
			return nil
		}

		tokenResponse = r.oauthProvider.ExchangeRefreshTokenForNewTokens(refreshToken, r.ClientId, r.ClientSecret)

		// Cache the token response for current access token accessTokenId
		r.KVStore.Put(REFRESH_RESPONSE_PREFIX+accessTokenId, toJsonString(tokenResponse))
	}

	r.Locker.Unlock(accessTokenId)
	//=== Critical section ends ===

	// Validate new access token
	newDecodedToken, err := r.validateAccessToken(tokenResponse.AccessToken)
	if err != nil {
		slog.Error("refreshed access token is invalid: %v", err)
		return nil
	}

	accessTokenCookie := tokenResponse.AccessToken
	if r.EncryptAccessTokenCookie {
		accessTokenCookie = r.jweEncryptor.Encrypt(accessTokenCookie)
	}

	// Write new access token cookie
	r.cookieManager.writeCookie(w, r.JwtCookieName, accessTokenCookie)

	// Store new refresh token if not already cached
	if tokenResponse.RefreshToken != "" && cachedTokenResponse == "" {
		r.storeRefreshToken(newDecodedToken, tokenResponse.RefreshToken)
	}

	return newDecodedToken
}

func (r *OAuthRequestInterceptor) setPostLoginUrlCookie(w http.ResponseWriter, rq *http.Request) {
	if r.WebAppBaseUrl != "" {
		u := r.WebAppBaseUrl
		if !strings.HasSuffix(u, "/") {
			u += "/"
		}

		u += rq.URL.Path

		if rq.URL.RawQuery != "" {
			u += "?" + rq.URL.RawQuery
		}

		r.cookieManager.writeCookie(w, r.PostLoginUrlCookieName, url.QueryEscape(u))
	}
}

func (r *OAuthRequestInterceptor) redirectToIdp(w http.ResponseWriter, rq *http.Request) {

	// store original full request URL so we can return after login
	// Prefer Origin header, fall back to Referer, then reconstruct from request
	origin := rq.Header.Get("Origin")
	if origin == "" {
		if ref := rq.Header.Get("Referer"); ref != "" {
			if u, err := url.Parse(ref); err == nil && u.Scheme != "" && u.Host != "" {
				origin = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
			}
		}
	}
	if origin != "" {
		r.cookieManager.writeCookie(w, r.PostLoginUrlCookieName, url.QueryEscape(origin))
	}

	u, _ := uuid2.NewV7()
	state := u.String()
	authURL := r.oauthProvider.AuthorizationEndpoint + "?" +
		"response_type=code&" +
		"client_id=" + url.QueryEscape(r.ClientId) + "&" +
		"redirect_uri=" + url.QueryEscape(r.RedirectUrl) + "&" +
		"scope=" + url.QueryEscape("openid offline_access") + "&" +
		"state=" + url.QueryEscape(state)

	// Store state in kv store with TTL of 1 hour
	r.KVStore.PutWithTTL(OIDC_STATE_PREFIX+state, "1", 3600)

	if rq.URL.Path == "/oidc/whoami" {
		w.Header().Set("Location", authURL)

		// Return 200 OK with Location header for frontend to handle redirect
		// this is to avoid CORS issues with redirects in fetch
		w.WriteHeader(http.StatusOK)
		return
	} else {
		http.Redirect(w, rq, authURL, http.StatusFound)
	}
}

func (r *OAuthRequestInterceptor) handleOidcRedirect(w http.ResponseWriter, rq *http.Request) {
	code := rq.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Bad request: no code received from OIDC provider", http.StatusBadRequest)
		return
	}

	state := rq.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "Bad request: no state received from OIDC provider", http.StatusBadRequest)
		return
	}

	stateExists := r.KVStore.Get(OIDC_STATE_PREFIX + state)
	if stateExists == "" {
		http.Error(w, "Invalid state received from OIDC provider", http.StatusBadRequest)
		return
	} else {
		// delete state from kv store
		r.KVStore.Del(OIDC_STATE_PREFIX + state)
	}

	// Exchange the authorization code for an ID tokenResponse
	tokenResponse := r.oauthProvider.ExchangeCodeForToken(code, r.ClientId, r.ClientSecret, r.RedirectUrl)
	cookieValue := tokenResponse.AccessToken
	decodedToken, err := r.validateAccessToken(tokenResponse.AccessToken)

	if r.EncryptAccessTokenCookie {
		cookieValue = r.jweEncryptor.Encrypt(cookieValue)
	}

	r.cookieManager.writeCookie(w, r.JwtCookieName, cookieValue)

	if tokenResponse.RefreshToken != "" {
		r.storeRefreshToken(decodedToken, tokenResponse.RefreshToken)
	}

	cookie, err := rq.Cookie(r.PostLoginUrlCookieName)
	if err == nil && cookie.Value != "" {
		r.cookieManager.deleteCookie(w, r.PostLoginUrlCookieName)

		decodedValue, err := url.QueryUnescape(cookie.Value)
		if err != nil {
			http.Error(w, "Failed to decode redirect URL from cookie: "+err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, rq, decodedValue, http.StatusFound)
		return
	} else {
		http.Redirect(w, rq, r.PostLoginPath, http.StatusFound)
	}
}

func (r *OAuthRequestInterceptor) storeRefreshToken(decodedToken *jwt.Token, refreshToken string) {
	claims, ok := decodedToken.Claims.(jwt.MapClaims)
	panics.OnFalse(ok, "failed to decode access token")
	jti, ok := claims["jti"].(string)
	if ok && jti != "" {
		r.KVStore.Put(REFRESH_TOKEN_PREFIX+jti, refreshToken)
	}
}

func (r *OAuthRequestInterceptor) fetchRefreshToken(jti string) (string, error) {
	refreshToken := r.KVStore.Get(REFRESH_TOKEN_PREFIX + jti)

	if refreshToken == "" {
		return "", fmt.Errorf("refresh token not found for jti: %s", jti)
	}

	return refreshToken, nil
}

func (r *OAuthRequestInterceptor) validateAccessToken(token string) (*jwt.Token, error) {

	// split the token into parts
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode the header to get the kid (key id)
	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	panics.OnError(err, "failed to decode JWT header")
	var header struct {
		Kid string `json:"kid"`
	}

	err = json.Unmarshal(decoded, &header)
	panics.OnError(err, "failed to unmarshal JWT header")
	panics.OnFalse(header.Kid != "", "no kid found in token header")

	// Fetch the JWK from the OIDC provider
	jwk := r.oauthProvider.GetKey(header.Kid)

	// parse and verify the token
	verifiedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return jwk.Key, nil
	})

	if err != nil {
		return verifiedToken, err
	}

	return verifiedToken, nil
}

func (r *OAuthRequestInterceptor) getTokenFromHeader(rq *http.Request) string {
	//read the Authorization header
	authorizationHeader := rq.Header.Get("Authorization")
	if authorizationHeader == "" {
		return ""
	}
	tokenString := authorizationHeader[len("Bearer "):]
	return tokenString
}

func (r *OAuthRequestInterceptor) getTokenFromCookie(rq *http.Request) string {
	cookie, err := rq.Cookie(r.JwtCookieName)
	if err != nil {
		return ""
	}
	// cookie contents is the token
	return cookie.Value
}

func (r *OAuthRequestInterceptor) deleteOidcCookies(w http.ResponseWriter) {
	r.cookieManager.deleteCookie(w, r.PostLoginUrlCookieName)
	r.cookieManager.deleteCookie(w, r.JwtCookieName)
}

func toJson(w io.Writer, v any) {
	encoder := json.NewEncoder(w)
	err := encoder.Encode(v)
	panics.OnError(err, "error encoding JSON")
}

func toJsonString(v any) string {
	buf := &bytes.Buffer{}
	toJson(buf, v)
	return buf.String()
}
