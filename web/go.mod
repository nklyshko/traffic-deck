module github.com/nklyshko/traffic-deck/web

go 1.25.0

require (
	github.com/nklyshko/traffic-deck/gateway v0.0.0
	google.golang.org/grpc v1.76.0
	google.golang.org/protobuf v1.36.11
)

require (
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250804133106-a7a43d27e69b // indirect
)

// Built from the same tree as the gateway, so the contract never drifts from it.
replace github.com/nklyshko/traffic-deck/gateway => ../gateway
