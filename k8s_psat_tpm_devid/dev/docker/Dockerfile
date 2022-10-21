FROM --platform=linux/amd64 golang:1.16.4-alpine3.13 as build

ARG BINARY
ARG TARGETOS
ARG TARGETARCH

ENV binary_env=$binary

RUN apk --no-cache add make && \
    mkdir /app

WORKDIR /app
COPY . .

RUN TARGETOS=${TARGETOS} TARGETARCH=${TARGETARCH} BINARY=${BINARY} make docker-build

FROM alpine:3.13

WORKDIR /app

ARG BINARY
ENV BINARY_ENV=${BINARY}

COPY --from=build /app/${BINARY_ENV} ./${BINARY_ENV}


ENTRYPOINT ["tail", "-f", "/dev/null"]
