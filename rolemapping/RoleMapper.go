package rolemapping

import "github.com/golang-jwt/jwt/v5"

type RoleMapper interface {
	GetRoles(principal string, token *jwt.Token) string
	Init()
}
