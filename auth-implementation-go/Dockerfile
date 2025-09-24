FROM golang:1.24.0 AS builder 

RUN mkdir /login 

WORKDIR /login 

COPY . .

RUN go build -o login.exe main.go

FROM ubuntu:latest AS base 

RUN apt update -y && apt install openssl -y

RUN apt install ca-certificates -y 

RUN update-ca-certificates

WORKDIR /

RUN mkdir /login

COPY --from=builder /login/config.json /login

COPY --from=builder /login/login.exe .

CMD [ "./login.exe" ]
