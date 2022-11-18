FROM golang:1.19-buster as builder
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . ./
RUN export CGO_ENABLED=0 && go build -v -o git-gateway

FROM gcr.io/distroless/static-debian11:nonroot
WORKDIR /app
COPY --from=builder /app/git-gateway /app/git-gateway
USER nonroot:nonroot
CMD ["/app/git-gateway"]