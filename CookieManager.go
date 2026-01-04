package oauth

import (
	"fmt"
	"net/http"

	"github.com/rizvn/panics"
)

type CookieManager struct {
	SecureCookies bool
}

func (r *CookieManager) Init() {

}

func (r *CookieManager) writeCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.SecureCookies,
	})
}

func (r *CookieManager) deleteCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.SecureCookies,
		MaxAge:   -1,
	})
}

func (r *CookieManager) readCookie(rq *http.Request, name string) string {
	cookie, err := rq.Cookie(name)
	panics.OnError(err, fmt.Sprintf("failed to read cookie %s", name))
	return cookie.Value
}
