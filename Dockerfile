FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-X github.com/whywaita/thatchbox/internal/cli.Version=${VERSION}" -o /thatchbox ./cmd/thatchbox
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /thatchbox /thatchbox
ENTRYPOINT ["/thatchbox"]
