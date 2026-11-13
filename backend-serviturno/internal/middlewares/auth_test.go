package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseAllowedOriginsRequiresExplicitOrigins(t *testing.T) {
	for _, value := range []string{"", " ", "*", "https://example.com/path", "file://example.com"} {
		if _, err := ParseAllowedOrigins(value); err == nil {
			t.Errorf("ParseAllowedOrigins(%q) succeeded, want error", value)
		}
	}

	origins, err := ParseAllowedOrigins("https://app.example.com, http://localhost:5501")
	if err != nil {
		t.Fatal(err)
	}
	if len(origins) != 2 {
		t.Fatalf("got %d origins, want 2", len(origins))
	}
}

func TestCORSRestrictsOriginsAndUnsafeRequests(t *testing.T) {
	allowedOrigins, err := ParseAllowedOrigins("https://app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	called := false
	handler := EnableCORS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}), allowedOrigins)

	tests := []struct {
		name       string
		method     string
		origin     string
		wantStatus int
		wantCalled bool
	}{
		{name: "trusted write", method: http.MethodPost, origin: "https://app.example.com", wantStatus: http.StatusNoContent, wantCalled: true},
		{name: "untrusted write", method: http.MethodPost, origin: "https://evil.example", wantStatus: http.StatusForbidden},
		{name: "write without origin", method: http.MethodPost, wantStatus: http.StatusForbidden},
		{name: "untrusted read", method: http.MethodGet, origin: "https://evil.example", wantStatus: http.StatusForbidden},
		{name: "trusted preflight", method: http.MethodOptions, origin: "https://app.example.com", wantStatus: http.StatusNoContent},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called = false
			request := httptest.NewRequest(test.method, "/api/test", nil)
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if called != test.wantCalled {
				t.Fatalf("next handler called = %v, want %v", called, test.wantCalled)
			}
			if test.origin == "https://evil.example" && response.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("untrusted origin received Access-Control-Allow-Origin")
			}
		})
	}
}
