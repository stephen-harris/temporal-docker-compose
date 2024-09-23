package auth

import (
	"fmt"
	"log/slog"
	"strings"
	"slices"
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/api/serviceerror"
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

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if authInfo.TLSConnection != nil {
		claims.Subject = authInfo.TLSSubject.CommonName
	}
	
	if authInfo.AuthToken == "" {
		return &claims, nil
	}
	
	// Extract token
	parts := strings.Split(authInfo.AuthToken, "Bearer ")
	if len(parts) != 2 {
		return nil, serviceerror.NewPermissionDenied("unexpected authorization token format", "")
	}
	jwtString := parts[1]
		
	// Read the token (with no validation) to check the issuer. 
	unverifiedToken, err := jwt.ParseInsecure([]byte(jwtString))
	if err != nil {
		logger.Info(fmt.Sprintf("Invalid Cognito JWT: %s", err))
		return nil, err
	}

	// We only use the issuer token to determine if its a Cognito / Kubernetes token
	// so we know how to validate it. We cannot use the iss value directly.
	if (unverifiedToken.Issuer() == os.Getenv("COGNITO_ISSUER_URL")) {
			
		token, err := VerifyCognitoToken(jwtString);

		if err != nil {
			logger.Info(fmt.Sprintf("Invalid Cognito JWT: %s", err))
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
			logger.Info(fmt.Sprintf("Invalid Kubernetes JWT: %s", err))
			return nil, err
		}

		rawkubernetesClaim, _ := token.Get("kubernetes.io")
		kubernetesClaim := rawkubernetesClaim.(KubernetesClaim)
			
		claims.System = authorization.RoleReader 
		claims.Namespaces = make(map[string]authorization.Role)
		claims.Namespaces[kubernetesClaim.Namespace] = authorization.RoleWriter
	}

	return &claims, nil
}
