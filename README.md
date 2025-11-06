# python-cloudflared-proxy

A FastAPI proxy that encrypts traffic before sending it through a Cloudflare tunnel and decrypts it on the server side. Useful for sharing a local HTTP service (like an LLM API) publicly while keeping payloads private when SSH and nginx somewhy are not an option.

## Quickstart

1. Install `cloudflared`:

```bash
./run_scripts/install_cloudflared.sh
```

2. Run the server proxy, change your key an iv to your 32 and 16 symbol passwords:

```bash
./run_scripts/run_server_proxy.sh
```

3. Start a Cloudflare tunnel:

```bash
./cloudflared tunnel --url http://localhost:8081
```

4. Run the client proxy (update target-url), key and iv must match server side proxy:

```bash
./run_scripts/run_client_proxy.sh
```

5. Send HTTP requests to the client proxy as usual.

## Architecture

```
Client App -> Client Proxy (encrypt) -> Cloudflare Tunnel -> Server Proxy (decrypt) -> Local Service
```

## Security & Compliance

* Encrypts only your own payloads.
* Do not proxy traffic you don’t own.
* Follow Cloudflare Terms of Use.

## Configuration

* `mode`, `listen-port`, `target-url`, `key`, `iv`

## Limitations

* Not for production or high-availability.

> **Note:** For educational and personal-use purposes only. Review Cloudflare's Terms of Use.
