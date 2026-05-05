FROM golang:1.25-alpine AS build
WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /server /server
COPY --from=build /workspace/config /config
ENV GO_CONFIG_DIR=/config
USER nonroot
EXPOSE 8080
EXPOSE 9090
ENTRYPOINT ["/server"]
