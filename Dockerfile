FROM golang:1.25.12-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/gateway ./cmd/gateway && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/backend ./cmd/backend && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/demo-oidc ./cmd/demo-oidc

FROM alpine:3.22

RUN apk add --no-cache ca-certificates
COPY --from=build /out/ /usr/local/bin/
WORKDIR /app
USER 65532:65532
CMD ["gateway"]
