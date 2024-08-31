build: test
	go build -o pscan cmd/scanner/main.go
test:
	go test -v ./...