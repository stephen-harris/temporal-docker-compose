ARG GOPROXY
ARG DOCKER_REGISTRY

### Golang target ###
FROM ${DOCKER_REGISTRY}golang:1.22.3 AS golang
RUN go version

WORKDIR /home/builder

COPY ./go* ./*.go ./
RUN go mod download

RUN CGO_ENABLED=0 go build -o jwt-issuer .

##### Temporal server #####
FROM ${DOCKER_REGISTRY}ubuntu:22.04 as jwt-issuer


# Set-up go
COPY --from=golang /usr/local/go/ /usr/local/go/
ENV PATH /usr/local/go/bin:$PATH
ENV GO111MODULE=on

SHELL ["/bin/bash", "-c"]

WORKDIR /etc/temporal

EXPOSE 3333

# TODO switch WORKDIR to /home/temporal and remove "mkdir" and "chown" calls.
RUN addgroup --gid 1000 jwtissuer
RUN adduser --uid 1000 --gid 1000 --disabled-password jwtissuer

# binaries
COPY --from=golang /home/builder/jwt-issuer /usr/local/bin


ENTRYPOINT ["jwt-issuer"]