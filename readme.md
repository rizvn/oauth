Example Usage

```go
package web

import (
	"github.com/rizvn/oauth"
	"github.com/gorilla/mux"
)

func main() {

    // Create a new OAuthRequestInterceptor
    interceptor := &oauth.OAuthRequestInterceptor{}

	// set optional env vars
	interceptor.SecureCookiesStr = os.Getenv("OIDC_SECURE_COOKIES") == "true"

	// set required env vars
	interceptor.ClientId     = os.Getenv("OIDC_CLIENT_ID")
	interceptor.ClientSecret = os.Getenv("OIDC_CLIENT_SECRET")
	interceptor.RedirectUrl  = os.Getenv("OIDC_REDIRECT_URL")
	interceptor.DiscoveryUrl = os.Getenv("OIDC_DISCOVERY_URL")

	// Check if access token cookie encryption is enabled
	interceptor.EncryptAccessTokenCookie = os.Getenv("OIDC_ENCRYPT_ACCESS_TOKEN_COOKIE") == "true"
	interceptor.EncryptionPublicKeyPath  = os.Getenv("OIDC_ENCRYPTION_PUBLIC_KEY")
	interceptor.EncryptionPrivateKeyPath = os.Getenv("OIDC_ENCRYPTION_PRIVATE_KEY")

    // Initialize the interceptor 
	interceptor.Init()
	
	
	router := mux.NewRouter()
    
    // Add the OAuth interceptor as middleware
    router.Use(interceptor.Interceptor)
	
}
```
```
