package auth

import (
	"context"
	"fmt"
	"os"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type CognitoClaim []string

func VerifyCognitoToken(tokenString string) (jwt.Token, error) {

	// TODO make this dynamic, but only from trusted sources (i.e. not the issuer in the token)
	var jwksURL = os.Getenv("COGNITO_ISSUER_URL") + "/.well-known/jwks.json";

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
		jwt.WithTypedClaim("cognito:groups", CognitoClaim{}),
  	)
  	if err != nil {
		fmt.Printf("failed to parse serialized: %s\n", err)
		return nil, err
 	}

	return tok, err
}




