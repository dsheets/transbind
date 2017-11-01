FROM golang:1.8-alpine

RUN apk add --no-cache git gcc musl-dev

WORKDIR /go/src/github.com/docker/editions.moby/alpine/packages/transbind
RUN go get -d -v \
    github.com/Sirupsen/logrus \
    github.com/pkg/errors \
    github.com/linuxkit/virtsock/pkg/vsock \
    github.com/docker/go-plugins-helpers/sdk \
    gopkg.in/dsheets/go-plugins-helpers.v999/mountpoint \
    gopkg.in/dsheets/docker.v999/volume/mountpoint
COPY . .
RUN CC=gcc go build --ldflags '-linkmode external -extldflags "-static"' \
    -o docker-mountpoint-transbind .

FROM alpine:3.5

RUN mkdir -p /run/docker/plugins/transbind
COPY --from=0 /go/src/github.com/docker/editions.moby/alpine/packages/transbind/docker-mountpoint-transbind docker-mountpoint-transbind

