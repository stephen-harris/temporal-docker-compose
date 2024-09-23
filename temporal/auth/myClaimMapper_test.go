package auth

import (
    "testing"
	"go.temporal.io/server/common/authorization"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"maps"
	"slices"
	"time"
	 "encoding/json"
	"crypto/rand"
	"crypto/rsa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwa"
)

func generateKeyPair() (jwk.Key, jwk.Key, error) {

	var kid = time.Now().Format("20060102150405")

	privKeyRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to generate private key: %s\n", err)
		return nil, nil, err
	}

	// Create private key
	privateKey, err := jwk.FromRaw(privKeyRaw)
	if err != nil {
		fmt.Printf("failed to create JWK: %s\n", err)
		return nil, nil, err
	}

	// Create public key
	publicKey, err := jwk.FromRaw(privKeyRaw.PublicKey)
	if err != nil {
		fmt.Printf("failed to create JWK: %s\n", err)
		return nil, nil, err
	}

	publicKey.Set(jwk.AlgorithmKey, jwa.RS256)
	publicKey.Set(jwk.KeyIDKey, kid)
	privateKey.Set(jwk.KeyIDKey, kid)

	return privateKey, publicKey, nil

}

func TestKubernetesToken(t *testing.T) {
	
	privateKey, publicKey, err := generateKeyPair()

	if err != nil {
		t.Fatalf(`failed to create key pair: %s\n`, err)
	}

	var keyset jwk.Set
	keyset = jwk.NewSet()
	keyset.AddKey(publicKey)

	publicKeySetJson, err := json.Marshal(keyset)
	if err != nil {
		t.Fatalf(`failed to convert JWK set to JSON: %s\n`, err)
	}

	// Create the token
	kc := &KubernetesClaim{
        Namespace: "some-client-namespace",
        Pod: KubernetesResource{
            Name: "pod-859cf6899d-sh5zl",
        },
		Serviceaccount: KubernetesResource{
            Name: "service-account-name",
        },
    }

	// Set up a test 'issuer' 
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, string(publicKeySetJson))
	}))
	defer srv.Close()
	os.Setenv("ISSUER_URL", srv.URL)
	os.Setenv("COGNITO_ISSUER_URL", "http://not.this.url")
	

	token, err := jwt.NewBuilder().
		Claim(`kubernetes.io`, kc).
		Subject(`system:serviceaccount:default:debug`).
		Expiration(time.Now().AddDate(1, 0, 0)).
		IssuedAt(time.Now()).
		Issuer(os.Getenv("ISSUER_URL")).
		Audience([]string{`temporal-service`}).
		Build()


	// Sign the token and generate a payload
	tokenString, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, privateKey))
	if err != nil {
		fmt.Printf("failed to generate signed payload: %s\n", err)
		os.Exit(1)
	}
	
	claimMaper := NewMyClaimMapper(nil)

	authInfo := &authorization.AuthInfo{
		AuthToken: `Bearer ` + string(tokenString),
	}

	claims, _:= claimMaper.GetClaims(authInfo)
	
	// Check read-only system access
	if (claims.System != authorization.RoleReader) {
		t.Fatalf(`Expected system role to be read only. Instead got %v`, claims.System)
	}

	// Check 'some-client-namespace' namespace has RoleWriter
	namespaceRole, _ := claims.Namespaces["some-client-namespace"];

	if (namespaceRole != authorization.RoleWriter) {
		t.Fatalf(`Expected namespace role to be RoleWriter. Instead got %v`, namespaceRole)
	}

	// Check no other namespaces have permission
	keys := slices.Collect(maps.Keys(claims.Namespaces))
	
	if (! slices.Equal(keys, []string{"some-client-namespace"})) {
		t.Fatalf(`Expected only some-client-namespace namespace. Found: %v`, keys)
	}

}

func TestAdminCognitoToken(t *testing.T) {
	

	privateKey, publicKey, err := generateKeyPair()

	if err != nil {
		t.Fatalf(`failed to create key pair: %s\n`, err)
	}

	var keyset jwk.Set
	keyset = jwk.NewSet()
	keyset.AddKey(publicKey)

	publicKeySetJson, err := json.Marshal(keyset)
	if err != nil {
		t.Fatalf(`failed to convert JWK set to JSON: %s\n`, err)
	}

	// Create the token
	cc := &CognitoClaim{
		"kaluza:mars",
		"kaluza:metering-industry-abstraction",
    }

	// Set up a test 'issuer' 
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, string(publicKeySetJson))
	}))
	defer srv.Close()
	os.Setenv("COGNITO_ISSUER_URL", srv.URL)

	token, err := jwt.NewBuilder().
		Claim(`cognito:groups`, cc).
		Subject(`c4a100b2-5241-4f28-9823-25f5a08be940`).
		Expiration(time.Now().AddDate(1, 0, 0)).
		IssuedAt(time.Now()).
		Issuer(os.Getenv("COGNITO_ISSUER_URL")).
	//	Audience([]string{`temporal-service`}).
		Build()


	// Sign the token and generate a payload
	tokenString, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, privateKey))
	if err != nil {
		fmt.Printf("failed to generate signed payload: %s\n", err)
		os.Exit(1)
	}
	
	claimMaper := NewMyClaimMapper(nil)

	authInfo := &authorization.AuthInfo{
		AuthToken: `Bearer ` + string(tokenString),
	}

	claims, _:= claimMaper.GetClaims(authInfo)
	
	// Check admin system access
	if (claims.System != authorization.RoleAdmin) {
		t.Fatalf(`Expected system role to be admin. Instead got %v`, claims.System)
	}
}

func TestNonAdminCognitoToken(t *testing.T) {
	

	privateKey, publicKey, err := generateKeyPair()

	if err != nil {
		t.Fatalf(`failed to create key pair: %s\n`, err)
	}

	var keyset jwk.Set
	keyset = jwk.NewSet()
	keyset.AddKey(publicKey)

	publicKeySetJson, err := json.Marshal(keyset)
	if err != nil {
		t.Fatalf(`failed to convert JWK set to JSON: %s\n`, err)
	}

	// Create the token
	cc := &CognitoClaim{
		"kaluza:migration-tooling",
    }

	// Set up a test 'issuer' 
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, string(publicKeySetJson))
	}))
	defer srv.Close()
	os.Setenv("COGNITO_ISSUER_URL", srv.URL)

	token, err := jwt.NewBuilder().
		Claim(`cognito:groups`, cc).
		Subject(`c4a100b2-5241-4f28-9823-25f5a08be940`).
		Expiration(time.Now().AddDate(1, 0, 0)).
		IssuedAt(time.Now()).
		Issuer(os.Getenv("COGNITO_ISSUER_URL")).
	//	Audience([]string{`temporal-service`}).
		Build()


	// Sign the token and generate a payload
	tokenString, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, privateKey))
	if err != nil {
		fmt.Printf("failed to generate signed payload: %s\n", err)
		os.Exit(1)
	}
	
	claimMaper := NewMyClaimMapper(nil)

	authInfo := &authorization.AuthInfo{
		AuthToken: `Bearer ` + string(tokenString),
	}

	claims, _:= claimMaper.GetClaims(authInfo)
	
	// Check admin system access
	if (claims.System != authorization.RoleReader) {
		t.Fatalf(`Expected system role to be read only. Instead got %v`, claims.System)
	}
		
	// Check 'migration-tooling-ns' namespace has RoleWriter
	namespaceRole, _ := claims.Namespaces["migration-tooling-ns"];

	if (namespaceRole != authorization.RoleWriter) {
		t.Fatalf(`Expected namespace to have role writer access to migration-tooling-ns namespace. Instead got %v`, namespaceRole)
	}

	// Check no other namespaces have permission
	keys := slices.Collect(maps.Keys(claims.Namespaces))
	
	if (! slices.Equal(keys, []string{"migration-tooling-ns"})) {
		t.Fatalf(`Expected only migration-tooling-ns namespace. Found: %v`, keys)
	}
}
