FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-s -w -X github.com/whywaita/thatchbox/internal/cli.Version=${VERSION}" \
    -o /thatchbox ./cmd/thatchbox

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /thatchbox /thatchbox
ENTRYPOINT ["/thatchbox"]
