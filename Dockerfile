# build stage
FROM golang:1.17-alpine AS build-env
RUN apk update && apk upgrade && \
    apk add --no-cache git

WORKDIR $GOPATH/src/github.com/autocert/controller
RUN go version
COPY go.mod go.sum ./
COPY controller/client.go controller/main.go ./
RUN go build -o /server .

# final stage
FROM smallstep/step-cli:0.17.2
ENV STEPPATH="/home/step"
ENV PWDPATH="/home/step/password/password"
ENV CONFIGPATH="/home/step/autocert/config.yaml"
COPY --from=build-env /server .
ENTRYPOINT ./server $CONFIGPATH
