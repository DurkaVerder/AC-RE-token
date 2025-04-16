FROM go1.23.3

WORKDIR /app

COPY . .

RUN go mod tidy

RUN go build -o main ./cmd/main.go

CMD [ "./main" ]



