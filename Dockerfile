# syntax=docker/dockerfile:1
FROM golang:1.19
WORKDIR /GitArrayTest
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY *.go ./
COPY *.db ./
EXPOSE 8080
RUN apt-get update && apt-get -y install gcc
RUN go build -o /main.go
CMD [ "/main.go" ]