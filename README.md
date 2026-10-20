ConnByte for [`libdns`](https://github.com/libdns/libdns)
=======================

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/libdns/connbyte)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for [ConnByte](https://connbyte.com/), allowing you to manage DNS records with the [ConnByte DNS API](https://api.connbyte.com/).

## Authenticating

Create an API token in your [ConnByte](https://connbyte.com/) account. The token needs access to the DNS zones you want to manage.

## Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/libdns/connbyte"
	"github.com/libdns/libdns"
)

func main() {
	provider := &connbyte.Provider{APIToken: os.Getenv("CONNBYTE_TOKEN")}

	recs, err := provider.AppendRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "token", TTL: 2 * time.Minute},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(recs)
}
```

## Notes

- Supported record types: `A`, `AAAA`, `CNAME`, `MX`, `NS`, `SRV`, `TXT`.
- TTLs are clamped to the API range of 60 to 86400 seconds. A TTL of 0 means 3600 seconds.
- The API has no batch operations. `SetRecords` and `DeleteRecords` are not atomic.
- `ListZones` is supported.
