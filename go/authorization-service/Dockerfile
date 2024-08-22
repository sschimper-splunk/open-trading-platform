FROM --platform=linux/arm64 golang:1.21

ADD . /app

WORKDIR /app

RUN go build -o service
RUN go test ./...
RUN go vet ./... 

CMD /app/service
