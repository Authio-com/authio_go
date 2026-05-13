# authio-go

Authio Go server SDK. Mirrors the [Authio OpenAPI](https://github.com/tcast/authio_proto) surface for backends written in Go.

## Install

```bash
go get github.com/tcast/authio_go
```

## Quick start

```go
import authio "github.com/tcast/authio_go"

client, _ := authio.New(os.Getenv("AUTHIO_SECRET_KEY"))
mems, err := client.ListMemberships(ctx, "user_01HX...")
```

## Multi-org-aware

A user belongs to many organizations. `Session.UserID` always identifies the
person; `Session.OrgID` is the active organization, which can be empty when
the user has authenticated but not yet selected an org. Use `client.AddMember`
and the `/v1/sessions/switch-org` endpoint to manage the multi-org lifecycle.

## License

MIT
