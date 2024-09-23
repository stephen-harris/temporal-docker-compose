package auth

import (
	"context"
	"fmt"
	"os"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type KubernetesClaim struct {
	Namespace string
	Pod KubernetesResource
	Serviceaccount KubernetesResource
}

type KubernetesResource struct {
	Name string
}

func VerifyK8sToken(tokenString string) (jwt.Token, error) {

	// TODO make this dynamic, but only from trusted sources (i.e. not the issuer in the token)
	//const jwksURL = "https://oidc.eks.eu-west-1.amazonaws.com/id/DBC6015902903F031E2D0F0CFCDA2044/keys"
	var jwksURL = os.Getenv("ISSUER_URL") + "/keys";//"http://localhost:3333/keys"

	// TODO cache this set
	set, err := jwk.Fetch(
		context.Background(),
		jwksURL,
	)

	if err != nil {
		fmt.Printf("failed to retrieve key set: %s\n", err)
		return nil, err
 	}

	tok, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithKeySet(set), 
		jwt.WithAudience("temporal-service"),
		jwt.WithTypedClaim("kubernetes.io", KubernetesClaim{}),
  	)
  	if err != nil {
		fmt.Printf("failed to parse serialized: %s\n", err)
		return nil, err
 	}

	return tok, err
}




