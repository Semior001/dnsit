FROM golang:1.22-alpine AS builder
LABEL maintainer="Semior <ura2178@gmail.com>"

ENV CGO_ENABLED=0

LABEL maintainer="Semior <ura2178@gmail.com>"

WORKDIR /srv

RUN apk add --no-cache --update git bash curl tzdata && \
    cp /usr/share/zoneinfo/Asia/Almaty /etc/localtime && \
    rm -rf /var/cache/apk/*

COPY ./app     /srv/app
COPY ./main.go /srv/main.go
COPY ./go.mod  /srv/go.mod
COPY ./go.sum  /srv/go.sum

COPY ./.git/ /srv/.git

RUN \
    export version="$(git describe --tags --long)" && \
    echo "version: $version" && \
    go build -o /go/build/dnsit -ldflags "-X 'main.version=${version}' -s -w" /srv/main.go

FROM alpine:3.14
LABEL maintainer="Semior <ura2178@gmail.com>"

RUN apk add --no-cache --update tzdata && \
    cp /usr/share/zoneinfo/Asia/Almaty /etc/localtime && \
    rm -rf /var/cache/apk/*

COPY --from=builder /go/build/dnsit /usr/bin/dnsit

ENV CONFIG=/srv/config

ENTRYPOINT ["/usr/bin/dnsit"]