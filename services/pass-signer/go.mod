module github.com/dynolabs-io/api/services/pass-signer

go 1.22

require (
	github.com/dynolabs-io/api/shared v0.0.0
	go.mozilla.org/pkcs7 v0.9.0
)

require github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e

require golang.org/x/image v0.18.0

require golang.org/x/text v0.16.0 // indirect

replace github.com/dynolabs-io/api/shared => ../../shared
