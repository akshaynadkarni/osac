package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateFulfillmentFlags(t *testing.T) {
	t.Run("all empty is valid", func(t *testing.T) {
		if err := validateFulfillmentFlags("", "", "", ""); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("all set is valid", func(t *testing.T) {
		err := validateFulfillmentFlags("ep", "id", "/path", "https://issuer")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("only client-id set returns error", func(t *testing.T) {
		err := validateFulfillmentFlags("", "id", "", "")
		if err == nil {
			t.Fatal("expected error when only client-id is set")
		}
	})

	t.Run("only secret-file set returns error", func(t *testing.T) {
		err := validateFulfillmentFlags("", "", "/path", "")
		if err == nil {
			t.Fatal("expected error when only secret-file is set")
		}
	})

	t.Run("only issuer-url set returns error", func(t *testing.T) {
		err := validateFulfillmentFlags("", "", "", "https://issuer")
		if err == nil {
			t.Fatal("expected error when only issuer-url is set")
		}
	})

	t.Run("missing issuer-url returns error", func(t *testing.T) {
		err := validateFulfillmentFlags("", "id", "/path", "")
		if err == nil {
			t.Fatal("expected error when issuer-url is missing")
		}
	})

	t.Run("endpoint without credentials returns error", func(t *testing.T) {
		err := validateFulfillmentFlags("fulfillment.svc:8000", "", "", "")
		if err == nil {
			t.Fatal("expected error when endpoint is set without credentials")
		}
	})

	t.Run("endpoint with credentials is valid", func(t *testing.T) {
		err := validateFulfillmentFlags(
			"fulfillment.svc:8000", "id", "/path", "https://issuer",
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("credentials without endpoint is valid", func(t *testing.T) {
		// Credentials set but no endpoint — valid (credentials are unused
		// but not an error; the driver simply won't dial).
		err := validateFulfillmentFlags("", "id", "/path", "https://issuer")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestBuildTokenURL(t *testing.T) {
	t.Run("without trailing slash", func(t *testing.T) {
		got, err := buildTokenURL("https://keycloak.example.com/realms/myrealm")
		if err != nil {
			t.Fatalf("buildTokenURL() returned error: %v", err)
		}
		want := "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token"
		if got != want {
			t.Fatalf("buildTokenURL() = %q, want %q", got, want)
		}
	})

	t.Run("with trailing slash", func(t *testing.T) {
		got, err := buildTokenURL("https://keycloak.example.com/realms/myrealm/")
		if err != nil {
			t.Fatalf("buildTokenURL() returned error: %v", err)
		}
		want := "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token"
		if got != want {
			t.Fatalf("buildTokenURL() = %q, want %q", got, want)
		}
	})

	for _, issuerURL := range []string{
		"http://keycloak.example.com/realms/myrealm",
		"https://",
		"https://keycloak.example.com/realms/myrealm?query=value",
	} {
		t.Run("rejects "+issuerURL, func(t *testing.T) {
			if _, err := buildTokenURL(issuerURL); err == nil {
				t.Fatalf("buildTokenURL(%q) returned no error", issuerURL)
			}
		})
	}
}

func TestNewTokenHTTPClient(t *testing.T) {
	if got := newTokenHTTPClient(false).Timeout; got != tokenHTTPTimeout {
		t.Fatalf("token HTTP timeout = %s, want %s", got, tokenHTTPTimeout)
	}
	if got := newTokenHTTPClient(true).Timeout; got != tokenHTTPTimeout {
		t.Fatalf("insecure token HTTP timeout = %s, want %s", got, tokenHTTPTimeout)
	}
}

func TestTokenHTTPClientRejectsCredentialRedirects(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var targetRequests int
			var targetAuth string
			var targetBody []byte
			target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetRequests++
				targetAuth = r.Header.Get("Authorization")
				targetBody, _ = io.ReadAll(r.Body)
			}))
			defer target.Close()

			source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", target.URL)
				w.WriteHeader(status)
			}))
			defer source.Close()

			req, err := http.NewRequest(
				http.MethodPost,
				source.URL,
				strings.NewReader("client_id=client&client_secret=secret"),
			)
			if err != nil {
				t.Fatalf("creating request: %v", err)
			}
			req.Header.Set("Authorization", "Basic credentials")

			resp, err := newTokenHTTPClient(true).Do(req)
			if err == nil {
				if resp != nil {
					resp.Body.Close()
				}
				t.Fatalf("expected redirect to be rejected")
			}
			if resp != nil {
				resp.Body.Close()
			}
			if targetRequests != 0 {
				t.Fatalf("redirect target received %d requests", targetRequests)
			}
			if targetAuth != "" || len(targetBody) != 0 {
				t.Fatalf("redirect target received credentials")
			}
		})
	}
}

func TestNewClientCredentialsTokenSource(t *testing.T) {
	t.Run("valid inputs produce a token source", func(t *testing.T) {
		dir := t.TempDir()
		secretFile := filepath.Join(dir, "client-secret")
		if err := os.WriteFile(secretFile, []byte("test-secret\n"), 0o600); err != nil {
			t.Fatalf("writing secret file: %v", err)
		}

		ts, err := newClientCredentialsTokenSource(
			context.Background(),
			"osac-csi-driver",
			secretFile,
			"https://keycloak.example.com/realms/myrealm",
			false,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ts == nil {
			t.Fatal("expected non-nil token source")
		}
	})

	t.Run("missing secret file returns error", func(t *testing.T) {
		_, err := newClientCredentialsTokenSource(
			context.Background(),
			"osac-csi-driver",
			"/nonexistent/path/secret",
			"https://keycloak.example.com/realms/myrealm",
			false,
		)
		if err == nil {
			t.Fatal("expected error for missing secret file")
		}
	})

	t.Run("empty secret file returns error", func(t *testing.T) {
		dir := t.TempDir()
		secretFile := filepath.Join(dir, "client-secret")
		if err := os.WriteFile(secretFile, []byte(""), 0o600); err != nil {
			t.Fatalf("writing secret file: %v", err)
		}

		_, err := newClientCredentialsTokenSource(
			context.Background(),
			"osac-csi-driver",
			secretFile,
			"https://keycloak.example.com/realms/myrealm",
			false,
		)
		if err == nil {
			t.Fatal("expected error for empty secret file")
		}
	})

	t.Run("whitespace-only secret file returns error", func(t *testing.T) {
		dir := t.TempDir()
		secretFile := filepath.Join(dir, "client-secret")
		if err := os.WriteFile(secretFile, []byte("  \n\t  \n"), 0o600); err != nil {
			t.Fatalf("writing secret file: %v", err)
		}

		_, err := newClientCredentialsTokenSource(
			context.Background(),
			"osac-csi-driver",
			secretFile,
			"https://keycloak.example.com/realms/myrealm",
			false,
		)
		if err == nil {
			t.Fatal("expected error for whitespace-only secret file")
		}
	})

	t.Run("insecureSkipVerify true produces a token source", func(t *testing.T) {
		dir := t.TempDir()
		secretFile := filepath.Join(dir, "client-secret")
		if err := os.WriteFile(secretFile, []byte("test-secret\n"), 0o600); err != nil {
			t.Fatalf("writing secret file: %v", err)
		}

		ts, err := newClientCredentialsTokenSource(
			context.Background(),
			"osac-csi-driver",
			secretFile,
			"https://keycloak.example.com/realms/myrealm",
			true,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ts == nil {
			t.Fatal("expected non-nil token source")
		}
	})
}

func TestDialFulfillment(t *testing.T) {
	t.Run("without credentials succeeds", func(t *testing.T) {
		conn, err := dialFulfillment("dns:///localhost:8000", false, "", "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if conn == nil {
			t.Fatal("expected non-nil connection")
		}
		conn.Close()
	})

	t.Run("with valid credentials succeeds", func(t *testing.T) {
		dir := t.TempDir()
		secretFile := filepath.Join(dir, "client-secret")
		if err := os.WriteFile(secretFile, []byte("test-secret"), 0o600); err != nil {
			t.Fatalf("writing secret file: %v", err)
		}

		conn, err := dialFulfillment(
			"dns:///localhost:8000", false,
			"osac-csi-driver", secretFile,
			"https://keycloak.example.com/realms/myrealm",
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if conn == nil {
			t.Fatal("expected non-nil connection")
		}
		conn.Close()
	})

	t.Run("with missing secret file returns error", func(t *testing.T) {
		_, err := dialFulfillment(
			"dns:///localhost:8000", false,
			"osac-csi-driver", "/nonexistent/secret",
			"https://keycloak.example.com/realms/myrealm",
		)
		if err == nil {
			t.Fatal("expected error for missing secret file")
		}
	})
}

func TestParseBackendMap(t *testing.T) {
	t.Run("empty string returns empty map", func(t *testing.T) {
		m, err := parseBackendMap("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(m) != 0 {
			t.Fatalf("expected empty map, got %v", m)
		}
	})

	t.Run("single pair", func(t *testing.T) {
		m, err := parseBackendMap("ontap=/csi/trident/csi.sock")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if m["ontap"] != "/csi/trident/csi.sock" {
			t.Fatalf("expected ontap=/csi/trident/csi.sock, got %v", m)
		}
	})

	t.Run("multiple pairs", func(t *testing.T) {
		m, err := parseBackendMap("ontap=/csi/trident/csi.sock,local=none")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(m) != 2 {
			t.Fatalf("expected 2 pairs, got %d", len(m))
		}
	})

	t.Run("invalid pair returns error", func(t *testing.T) {
		_, err := parseBackendMap("invalid-no-equals")
		if err == nil {
			t.Fatal("expected error for invalid pair")
		}
	})
}
