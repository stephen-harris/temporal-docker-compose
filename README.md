# Temporal Authentication (Custom Claim Mapper)

## How it works

### Machine to Machine

Clients and workers auto-mount tokens, issued by kube-apiserver. These must have the `temporal-service` audience. This can be done by adding the following to a client/worker's pod spec:

```yaml
    ...
    spec:
      serviceAccountName: debug
      containers:
      - name: container-name
        ...
        volumeMounts:
          - mountPath: /var/run/secrets/tokens
            name: temporal-service-token
      volumes:
      - name: temporal-service-token
        projected:
          sources:
          - serviceAccountToken:
              path: temporal-service-token
              expirationSeconds: 7200 # 2 hours
              audience: temporal-service
```

In this example the token must be reread before it expires (Kubernetes rotates tokens when they are at 80% of TTL).

In this docker compose example, the `jwt-issuer` generates a token and persists it to a local directory to be read by the client/workers.

The custom claim maper (see `temporal` directory) verifies the signature of the token using the public key set exposed by EKS (again the jwt-issuer service performs this role locally) and validates the audience and (Kubernetes) namespace. It assigns write permissions to the client for that namespace only (assuming a 1-1 mapping between Kubernetes namespace and Temporal namespace).

When running in a Kubernetes cluster the token will be rotated automatically, and so client/workers will need to periodically re-read the token.


### User to Machine

TODO. The basic premise is that the Temporal can be integrated with SSO (via Cognito backed by Google). This will give us an identity token for a user, along with any teams they belong to. We will need some configuration, performed at the point of onboarding, which maps a team to Temporal namespace. 


## Running locally

This repository will spin up Temporal service configured with mTLS and a custom claim mapper that will map Kubernetes namespaces to Temporal namespaces for Kubernetes-issued (i.e. machine-to-machine) tokens and Cognito groups to Temporal namespaces for Cognito issued (i.e. user-to-machine) tokens.

## Create certificates

Run the following command

```
./generate-test-certs.sh
```

to create a CA, and key/certs for temporal server and client.


## Run docker-compose

```
docker compose up --build
```
