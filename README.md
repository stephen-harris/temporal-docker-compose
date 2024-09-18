# Temporal Docker Compose


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