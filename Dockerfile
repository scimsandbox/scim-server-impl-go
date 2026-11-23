FROM golang:1.26.11-alpine AS build
WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /server ./cmd/server

FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5
COPY --from=build /server /server
COPY --from=build /workspace/config/app-conf.yaml /config/app-conf.yaml
ENV GO_CONFIG_DIR=/config
USER nonroot
EXPOSE 8080
EXPOSE 9090
ENTRYPOINT ["/server"]
