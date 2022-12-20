@echo off
go build -ldflags "-w -s" -o release/AvHunt.exe main.go

@echo off
SET CGO_ENABLED=0
SET GOOS=windows
SET GOARCH=386
go build -ldflags "-w -s" -o release/AvHunt32.exe main.go
