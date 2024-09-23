# JWT Issuer

This service signs a JWT token and persists to `$KEY_DIR/token`, where by using a shared volume can be accessed by clients/workers in their API requests to Temporal Server.

The service also exposes the public key on an endpoint `:3333/keys` so that our ClaimMapper can authenticate the claims in the JWT and map those to Temporal namespace permissions.

Effectivlely its mimicing the OIDC provider URL (by making the public key set accessiable) and the kubelet (which mounts the token on the pod)