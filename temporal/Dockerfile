ARG GOPROXY
ARG DOCKER_REGISTRY

### Golang target ###
FROM ${DOCKER_REGISTRY}golang:1.21 AS golang
RUN go version


##### Builder target #####
FROM ${DOCKER_REGISTRY}ubuntu:22.04 AS temporal-builder

# Install dependencies
RUN apt-get -qq update && apt-get -qq install -y curl git make


# Set-up go
COPY --from=golang /usr/local/go/ /usr/local/go/
ENV PATH /usr/local/go/bin:$PATH
ENV GO111MODULE=on

WORKDIR /home/builder

# cache Temporal packages as a docker layer
COPY ./go* ./*.go Makefile ./
RUN go mod download
COPY ./auth ./auth
RUN CGO_ENABLED=0 make temporal-server

##### Temporal server #####
FROM ${DOCKER_REGISTRY}ubuntu:22.04 as temporal-server

# Install dependencies
ENV TZ=Etc/UTC
ENV DEBIAN_FRONTEND=noninteractive
ENV DOCKERIZE_VERSION v0.8.0
RUN apt-get -qq update && apt-get -qq install -y curl git tzdata ca-certificates netcat gettext-base wget

USER root
RUN wget -O - https://github.com/jwilder/dockerize/releases/download/$DOCKERIZE_VERSION/dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz | tar xzf - -C /usr/local/bin
RUN apt-get autoremove -yqq --purge wget && rm -rf /var/lib/apt/lists/*

# Set-up go
COPY --from=golang /usr/local/go/ /usr/local/go/
ENV PATH /usr/local/go/bin:$PATH
ENV GO111MODULE=on

SHELL ["/bin/bash", "-c"]

WORKDIR /etc/temporal

ENV TEMPORAL_HOME /etc/temporal
ENV SERVICES "frontend"

# Membership ports used by the multiple services (frontend, history, matching, worker, internal-frontend)
EXPOSE 6933 6934 6935 6939 6936
# GRPC ports used by the multiple services (frontend, history, matching, worker, internal-frontend)
EXPOSE 7233 7234 7235 7239 7236

# TODO switch WORKDIR to /home/temporal and remove "mkdir" and "chown" calls.
RUN addgroup --gid 1000 temporal
RUN adduser --uid 1000 --gid 1000 --disabled-password temporal
RUN mkdir -p /etc/temporal/config

# binaries
COPY --from=temporal-builder /home/builder/temporal-server /usr/local/bin

# scripts
COPY ./scripts/entrypoint.sh /etc/temporal/entrypoint.sh
COPY ./scripts/start-temporal.sh /etc/temporal/start-temporal.sh

RUN chown -R temporal:temporal /etc/temporal
RUN chmod -R ugo+x /etc/temporal
USER temporal

ENTRYPOINT ["/etc/temporal/entrypoint.sh"]