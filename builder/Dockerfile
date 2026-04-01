FROM golang:1.24-alpine AS base

RUN apk add --no-cache git upx

# Install garble
RUN go install mvdan.cc/garble@latest

WORKDIR /app
COPY go.mod ./
RUN go mod download

COPY . .
RUN go build -o /sigil-builder ./cmd/sigil-builder/

FROM golang:1.24-alpine AS runtime

RUN apk add --no-cache git upx
COPY --from=base /root/go/bin/garble /usr/local/bin/garble
COPY --from=base /sigil-builder /usr/local/bin/sigil-builder
COPY --from=base /app/template /template

ENV SIGIL_TEMPLATE_DIR=/template

EXPOSE 8080
ENTRYPOINT ["sigil-builder", "serve"]
CMD ["--port", "8080"]
