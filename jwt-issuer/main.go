package main

import (
	"errors"
	"fmt"
	"time"
	 "encoding/json"
	"io"
	"net/http"
	"os"
	"crypto/rand"
	"crypto/rsa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwa"
)

var publicKeySetPath = string(os.Getenv("KEY_DIR")) + "/public.keyset.json";
var tokenPath = string(os.Getenv("KEY_DIR")) + "/token";

func main() {

	generateKeySetAndToken();

	http.HandleFunc("/keys", getKeysHandler)

	err := http.ListenAndServe(":3333", nil)

	if errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("server closed\n")
	} else if err != nil {
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}

}

type KubernetesClaim struct {
	Namespace string
	Pod KubernetesResrouce
	Serviceaccount KubernetesResrouce
}

type KubernetesResrouce struct {
	Name string
}


func generateKeySetAndToken() {

	privKeyRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to generate private key: %s\n", err)
		os.Exit(1)
	}

	var kid = time.Now().Format("20060102150405")

	privateKey, err := jwk.FromRaw(privKeyRaw)
	privateKey.Set(jwk.KeyIDKey, kid)

	if err != nil {
		fmt.Printf("failed to create JWK: %s\n", err)
		os.Exit(1)
	}

	pubKey, err := jwk.FromRaw(privKeyRaw.PublicKey)
	if err != nil {
		fmt.Printf("failed to create JWK: %s\n", err)
		return
	}
	pubKey.Set(jwk.AlgorithmKey, jwa.RS256)
	pubKey.Set(jwk.KeyIDKey, kid)

	var keyset jwk.Set
	keyset = jwk.NewSet()
	keyset.AddKey(pubKey)


	publicKeySetJson, err := json.Marshal(keyset)
	if err != nil {
		fmt.Printf("failed to convert JWK set to JSON: %s\n", err)
		os.Exit(1)
	}

	err = os.WriteFile(publicKeySetPath, publicKeySetJson, 0644)
	if err != nil {
		fmt.Printf("failed to persist JWK: %s\n", err)
		os.Exit(1)
	}

	// Create the token
	kc := &KubernetesClaim{
        Namespace: "default",
        Pod: KubernetesResrouce{
            Name: "pod-859cf6899d-sh5zl",
        },
		Serviceaccount: KubernetesResrouce{
            Name: "service-account-name",
        },
    }

	token, err := jwt.NewBuilder().
		Claim(`kubernetes.io`, kc).
		Subject(`system:serviceaccount:default:debug`).
		Expiration(time.Now().AddDate(1, 0, 0)).
		IssuedAt(time.Now()).
		Issuer(os.Getenv("ISSUER_URL")).
		Audience([]string{`temporal-service`}).
		Build()

	// Sign the token and generate a payload
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, privateKey))
	if err != nil {
		fmt.Printf("failed to generate signed payload: %s\n", err)
		os.Exit(1)
	}

	err = os.WriteFile(tokenPath, signed, 0644)
	if err != nil {
		fmt.Printf("failed to persist JWK: %s\n", err)
		os.Exit(1)
	}
}


func getKeysHandler(w http.ResponseWriter, r *http.Request) {
	publicKey, err := os.ReadFile(publicKeySetPath)
	if err != nil {
		fmt.Printf("failed to generate private key: %s\n", err)
		return
	}

	io.WriteString(w, string(publicKey))
}
