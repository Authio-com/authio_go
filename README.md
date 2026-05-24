<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/logo-dark.png">
    <img alt="Authio" src=".github/logo-light.png" width="220">
  </picture>
</p>

# authio-go

Authio Go server SDK. Mirrors the [Authio OpenAPI](https://github.com/authio-com/authio_proto) surface for backends written in Go.

## What's new — 2026-05-23 WorkOS-parity sprint

The OpenAPI source of truth ([`authio_proto`](https://github.com/authio-com/authio_proto)) gained four new product
surfaces this sprint:

- **Embeddable widgets** (`POST /v1/widget-tokens`, `GET /widget/*`) —
  see [docs.authio.com/widgets/overview](https://docs.authio.com/widgets/overview).
- **Synchronous customer-hosted Actions**
  (`POST /v1/session/actions` and the `pre_token_mint` HMAC envelope) —
  see [docs.authio.com/actions/overview](https://docs.authio.com/actions/overview).
  The Go signature-verification snippet is on
  [docs.authio.com/actions/signature-verification](https://docs.authio.com/actions/signature-verification).
- **Dynamic Client Registration + CIMD** (`/oauth2/register`,
  `/oauth2/cimd/resolve`) — see
  [docs.authio.com/concepts/dynamic-client-registration](https://docs.authio.com/concepts/dynamic-client-registration)
  and [docs.authio.com/concepts/client-id-metadata-document](https://docs.authio.com/concepts/client-id-metadata-document).
- **Roles + permissions catalog** (`/v1/session/roles`,
  `/v1/session/permissions`, `/v1/session/organizations/.../roles`) —
  see [docs.authio.com/concepts/roles-and-permissions](https://docs.authio.com/concepts/roles-and-permissions).

Idiomatic Go bindings for every new endpoint are coming in the next
release; in the meantime drive them via `client.Do(ctx, ...)` against
the OpenAPI shape.

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
