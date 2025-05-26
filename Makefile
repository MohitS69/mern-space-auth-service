build:
	go build -o ./bin/main 
start:
	./bin/main

run-script:
	go run scripts/*.go -arg=$(script)

generate-rsa-keys:
	make run-script script=$@

host-pubkey-locally:
	make run-script script=$@

