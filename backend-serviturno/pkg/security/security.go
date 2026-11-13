package security

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret []byte

func ConfigureJWTSecret(secret string) error {
	if len(strings.TrimSpace(secret)) < 32 {
		return errors.New("SERVITURNO_JWT_SECRET debe tener al menos 32 caracteres")
	}
	jwtSecret = []byte(secret)
	return nil
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GenerateJWT(userID int, rol string) (string, error) {
	if len(jwtSecret) < 32 {
		return "", errors.New("la clave JWT no está configurada")
	}
	claims := jwt.MapClaims{
		"user_id": userID,
		"rol":     rol,
		"exp":     time.Now().Add(time.Minute * 15).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func ValidateJWT(tokenStr string) (jwt.MapClaims, error) {
	if len(jwtSecret) < 32 {
		return nil, errors.New("la clave JWT no está configurada")
	}
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("método de firma inesperado")
		}
		return jwtSecret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil || !token.Valid {
		return nil, errors.New("token inválido o expirado")
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims, nil
	}
	return nil, errors.New("error procesando claims")
}
