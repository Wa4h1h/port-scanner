build: test
	go build -o scanner cmd/scanner/main.go
test:
	go test -v ./...