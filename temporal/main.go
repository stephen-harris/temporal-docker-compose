package main

import (
	"log"

	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/primitives"
	"go.temporal.io/server/common/config"
	"go.temporal.io/server/temporal"
	"service-samples/auth"
)

func main() {

	cfg, err := config.LoadConfig("docker", "/etc/temporal/config", "")
	if err != nil {
		log.Fatal(err)
	}

	s, err := temporal.NewServer(
		temporal.ForServices([]string{string(primitives.FrontendService)}),
		temporal.WithConfig(cfg),
		temporal.InterruptOn(temporal.InterruptCh()),
		temporal.WithClaimMapper(func(cfg *config.Config) authorization.ClaimMapper {
			return auth.NewMyClaimMapper(cfg)
		}),
		temporal.WithAuthorizer(authorization.NewDefaultAuthorizer()),
	)
	if err != nil {
		log.Fatal(err)
	}

	err = s.Start()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("All services are stopped.")
}