package auth

import (
	"fmt"
	"strings"
	"slices"
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/config"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"os"
)

type myClaimMapper struct{}

func NewMyClaimMapper(_ *config.Config) authorization.ClaimMapper {
	return &myClaimMapper{}
}

func (c myClaimMapper) GetClaims(authInfo *authorization.AuthInfo) (*authorization.Claims, error) {
	claims := authorization.Claims{}

	if authInfo.TLSConnection != nil {
		claims.Subject = authInfo.TLSSubject.CommonName
	}
	
	if authInfo.AuthToken != "" {
		jwtString := strings.Split(authInfo.AuthToken, "Bearer ")[1]

		tok, _ := jwt.Parse([]byte(jwtString), jwt.WithVerify(false))

		// Debug
		fmt.Println(jwtString)
		fmt.Println(tok.Audience());
		fmt.Println(tok.Issuer());
		fmt.Println(tok.Subject());
		
		if (tok.Issuer() == os.Getenv("COGNITO_ISSUER_URL")) {
			
			token, err := VerifyCognitoToken(jwtString);

			if err != nil {
				return nil, err
			}

			rawCognitoClaim, _ := token.Get("cognito:groups")
			cognitoClaim := rawCognitoClaim.(CognitoClaim)

			if (slices.Contains(cognitoClaim, "kaluza:metering-industry-abstraction")) {
				claims.System = authorization.RoleAdmin 

			} else if (slices.Contains(cognitoClaim, "kaluza:migration-tooling")) {

				claims.System = authorization.RoleReader

				//TODO mapping permissions based on cognito:groups
				claims.Namespaces = make(map[string]authorization.Role)
				claims.Namespaces["migration-tooling-ns"] = authorization.RoleWriter	
			}

		} else {
			// Assume its a m2m token (i.e. kubernetes mounted token)
			token, err := VerifyK8sToken(jwtString);

			if err != nil {
				return nil, err
			}

			rawkubernetesClaim, _ := token.Get("kubernetes.io")
			kubernetesClaim := rawkubernetesClaim.(KubernetesClaim)
			
			claims.System = authorization.RoleReader 
			claims.Namespaces = make(map[string]authorization.Role)
			claims.Namespaces[kubernetesClaim.Namespace] = authorization.RoleWriter
		}


	}

	return &claims, nil
}
