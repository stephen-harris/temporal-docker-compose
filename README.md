# Temporal Docker Compose


## Create certificates

Run the following command

```
./generate-test-certs.sh
```

to create a CA, and key/certs for temporal server and client.


## Build temporal server

This image is used with a custom authorizer/claim mapper.

```
docker build temporal -t my-temporal-server
```


