FROM golang:1.18-bullseye as build
RUN go install golang.org/x/lint/golint@latest
WORKDIR /build
COPY . ./
RUN make release

FROM debian:bullseye-slim
WORKDIR /
COPY --from=build /build/kube-sidecar-injector /

ENTRYPOINT ["/kube-sidecar-injector"]
