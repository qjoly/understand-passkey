# Understand Passkeys — with a Cup of Coffee

A single-page interactive web app that explains how passkeys (WebAuthn) work and lets you try them out in your browser.

## What is this?

An educational tool that covers:

- **Theory** — what passkeys are, how public-key cryptography replaces passwords, and why they resist phishing.
- **Registration & authentication flows** — step-by-step ASCII diagrams showing the browser/server/authenticator exchange.
- **Live demo** — register and log in with a real passkey right in the page. All data is stored in server memory and resets on restart.

## Tech stack

- **Backend:** Go, using [go-webauthn/webauthn](https://github.com/go-webauthn/webauthn)
- **Frontend:** Single HTML file with vanilla JS, no framework
- **Storage:** In-memory (no database)

## Getting started

### Run locally

```bash
go run main.go
```

The server starts on `http://localhost:8080` by default.

### Environment variables

| Variable    | Default                    | Description                          |
|-------------|----------------------------|--------------------------------------|
| `PORT`      | `8080`                     | HTTP listen port                     |
| `RP_ID`     | `localhost`                | WebAuthn Relying Party ID (domain)   |
| `RP_ORIGIN` | `http://localhost:<PORT>`  | Allowed origin for WebAuthn requests |

### Docker

```bash
docker build -t understand-passkey .
docker run -p 8080:8080 understand-passkey
```

## API endpoints

| Method | Path                    | Description                |
|--------|-------------------------|----------------------------|
| POST   | `/api/register/begin`   | Start passkey registration |
| POST   | `/api/register/finish`  | Complete registration      |
| POST   | `/api/login/begin`      | Start passkey login        |
| POST   | `/api/login/finish`     | Complete login             |
| GET    | `/api/users`            | List registered users      |
