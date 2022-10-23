FROM golang:1.19-alpine
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN apk add llvm clang make linux-headers \
    libbpf libbpf-dev musl musl-dev
RUN make build

FROM alpine
WORKDIR /src

COPY --from=0 /src/build/durdur /bin/durdur

ENTRYPOINT ["/bin/durdur"]
