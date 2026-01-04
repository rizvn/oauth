package rolemapping

import "github.com/golang-jwt/jwt/v5"

type NoopRoleMapper struct {
}

func (r *NoopRoleMapper) Init() {
}

func (r *NoopRoleMapper) GetRoles(principal string, token *jwt.Token) string {
	return ""
}
