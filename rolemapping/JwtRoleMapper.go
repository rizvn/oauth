package rolemapping

import (
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rizvn/panics"
)

// JwtRoleMapper is a role mapper that maps roles from JWT tokens.
// call Set methods to configure the mapper before calling Init().
type JwtRoleMapper struct {
	AllowIdpRolePrefixes  []string
	RemoveAppRolePrefixes []string
	PrependToAppRole      string
}

func (r *JwtRoleMapper) Init() {
	r.AllowIdpRolePrefixes = make([]string, 0)
	r.RemoveAppRolePrefixes = make([]string, 0)
}

func (r *JwtRoleMapper) SetAllowedRolePrefixes(allowedRolePrefixes string) {
	if allowedRolePrefixes != "" {
		for _, token := range strings.Split(allowedRolePrefixes, ",") {
			r.AllowIdpRolePrefixes = append(r.AllowIdpRolePrefixes, strings.TrimSpace(token))
		}
	}
}

func (r *JwtRoleMapper) SetRemoveAppRolePrefixes(removeAppRolePrefixes string) {
	if removeAppRolePrefixes != "" {
		for _, token := range strings.Split(removeAppRolePrefixes, ",") {
			r.RemoveAppRolePrefixes = append(r.RemoveAppRolePrefixes, strings.TrimSpace(token))
		}
	}
}

func (r *JwtRoleMapper) SetPrependToAppRole(prependToAppRole string) {
	r.PrependToAppRole = strings.TrimSpace(prependToAppRole)
}

func (r *JwtRoleMapper) GetRoles(principal string, token *jwt.Token) string {
	decodeClaims, ok := token.Claims.(jwt.MapClaims)
	panics.OnFalse(ok, "failed to decode access token claims")

	roles := ""
	claimsRoles, ok := decodeClaims["roles"].([]interface{})
	if !ok {
		roles += ""
	}
	for _, role := range claimsRoles {
		roles += role.(string)
	}
	return roles
}
