# Connect Hub kernel integration (P4, 2026-11-26)

This branch merges the two kernel sources used by Connect Hub. Baseline:
`feat/desktop-worker` at `9f433a08fa28528775b268a338610138b6c7f147`;
upstream ancestor `8576e7a16076c4175d6dbe276573a353cf7260be`.
Hub source: `refactor/component-boundaries` at `3d30acd`, embedded tree
`58f9689fff8ab20fcbf4e7b324589154963a8534`.
The original embedded tree remains recoverable from the Hub history.

The embedded copy is older than the Worker fork in several areas. This is an
additive merge, not a replacement of the fork by the embedded tree.

## Patch inventory

| Area / embedded paths | Decision and verification |
| --- | --- |
| `client/atrust/auth/{auth,request}.go` | Retain upstream context cancellation, authId/subType, MAC reporting/signature, RADIUS challenge chain and strict refresh validation. Add QR configuration/ticket extraction and online probe. `auth` context/refresh/Hub tests. |
| `client/atrust/auth/qywechat.go` | Port same-session WeCom flow, relative redirects and ticket/cookie handling. Restrict callback and follow-up requests to the configured HTTPS origin. `TestQyWechat*`. |
| `client/atrust/auth/{prompt,sms_prompt_test,custom_sms,sms_check_code,token}.go` | Bridge Hub CodePrompter to the existing handler flow; retain RSA-encrypted RADIUS challenge, skip-secondary semantics and SMS tips. SMS/primary/challenge/token tests. |
| `client/atrust/auth/{captcha_server,graph_check_code}.go` | Browser click captcha is an explicit SetupOptions opt-in; CLI/Worker handlers keep their existing defaults. Browser wait follows login cancellation. Graph-code and browser-cancellation tests. |
| `client/atrust/auth/login_method.go` | Add qywechat registration/callback. Existing login method tests and Hub external-login tests. |
| `client/atrust/auth/{cas,https_oauth2,device,enhanced,psw}.go` | Keep newer fork handlers, context propagation, MAC and password/RADIUS fixes. Hub already validates externally supplied callback origin. Existing auth tests. |
| `client/atrust/{client,parse}.go` | Port application/resource snapshots and saved-session probe; retain SetupContext, MAC and refresh. Export refreshed cookies under session lock; bind maintenance to owner lifetime after setup. Resource, refresh, Hub tests. |
| `client/atrust/{ip,l3tunnel,l3tunnelconn,node,tcptunnel}.go` | Keep caller context/current SID and newer tunnel logic; restore fake-to-real domain destination mapping. Invalid session exits are CLI opt-in so embedded Hub survives. Session exit and embedder error tests. |
| `client/easyconnect/{client,parse,protocol,request}.go` | Keep fork unchanged: verified TLS/pinning, interactive handler, TCP-only setup, IPv6 ownership. EasyConnect and pinnedcert tests. |
| `cmd/multitun/{main,resources,hidecmd_other,hidecmd_windows,platform_darwin,platform_windows}.go` | Port Hub multi-session TUN helper. Windows/macOS compile validation; real gateway/adapter testing remains separate. |
| `configs/config.go`, `init.go`, `main.go`, `service/tcp_forwarding.go` | Retain newer CLI configuration, secure file modes, caller lifecycle and resource-aware forwarding; CLI explicitly enables process-exit policy. Root/config/service tests. |
| `internal/ippool/ippool.go` | Keep fork bounded allocation/memory improvements; PreferFakeIP uses fallible AllocateIP. Pool/resolve tests. |
| `resolve/{resolver,internal_dns}.go` | Keep Worker split DNS, strict query ownership and bounded cache. Port PreferFakeIP; provide ConfigureInternalDomains for Hub's legacy packet resolver without changing Worker defaults. Split/strict/query-chain/shared-IP tests. No duplicate internal_dns.go. |
| `stack/gvisor/{dial,stack}.go` | Keep bounded TCP buffers, cancellation and IPv4 checks. Add explicit Hub L3 retry opt-in; retain packet-drop handling and standalone-only SHUTDOWN exit. Stack/dial tests. |
| `stack/tcptunnel/dial.go` | Keep fork TCP-only resource preference support. Hub uses gVisor and its resource-aware strict dialer. TCP stack/dial tests. |
| `stack/tun/{stack,stack_darwin,stack_windows,tcplistener}.go` | Port per-interface helper setup, hidden Windows commands, route replacement, fake-IP domain routing and non-panicking teardown. Preserve resource cache. Stack tests and cross builds. |
| `go.mod`, `go.sum` | Keep fork versions/replacements, including local patched uTLS. Hub explicitly selects the same uTLS source (dependency replacements are not inherited). Module manifests and pinnedcert tests. |
| `PATCH.md` | Superseded by this inventory; old claims of a v1.3.1-only, test-free patch were incomplete. |

Fork-only Worker IPC v7, UDP associations, IPv6 ownership, memory limit/pools and
certificate pinning remain intact. `third_party/utls/EASYCONNECT_PATCH.md`
documents the opt-in parser: ordinary TLS does not gain an insecure fallback.

## Validation and limits

Windows: `GOWORK=off go test ./...`. POSIX permission assertions in key-log/PCAP
tests only run on POSIX; Windows still checks contents and failure behavior.
Linux: race checks on aTrust/auth, EasyConnect, resolver, dial, network stacks,
desktop, pinnedcert and ippool. Hub's full Windows suite also passed against this
kernel and patched uTLS before replacing its embedded source.

No live gateway login, real captcha/WeCom browser interaction, session takeover,
privileged adapter/route installation or throughput acceptance was performed in
P4. These remain necessary before calling the merged kernel release-ready.
