package security

import "testing"

func TestJWTRequiresConfiguredSecret(t *testing.T) {
	jwtSecret = nil
	if _, err := GenerateJWT(1, "Administrador"); err == nil {
		t.Fatal("GenerateJWT() succeeded without a configured secret")
	}
	if _, err := ValidateJWT("token"); err == nil {
		t.Fatal("ValidateJWT() succeeded without a configured secret")
	}
	if err := ConfigureJWTSecret("short"); err == nil {
		t.Fatal("ConfigureJWTSecret() accepted a short secret")
	}
}

func TestJWTUsesConfiguredSecret(t *testing.T) {
	const secret = "test-only-signing-key-with-at-least-32-bytes"
	if err := ConfigureJWTSecret(secret); err != nil {
		t.Fatal(err)
	}

	token, err := GenerateJWT(7, "Administrador")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims["rol"] != "Administrador" {
		t.Fatalf("role claim = %v, want Administrador", claims["rol"])
	}

	if err := ConfigureJWTSecret("another-test-signing-key-with-32-bytes"); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateJWT(token); err == nil {
		t.Fatal("ValidateJWT() accepted a token signed with a previous secret")
	}
}
