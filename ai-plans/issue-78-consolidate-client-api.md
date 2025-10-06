# Overview

This plan is for [issue #78](https://github.com/tailscale/tsidp/issues/78): Consolidate endpoints for managing OAuth clients

There are two ways to manage IDPServer.funnelClients (server.go: line 61):

Method #1: the admin UI, served under /

- the admin UI calls /new, /edit/{id} to make changes
- the UI is basic server side rendered HTML with form POST to make changes

Method #2: The /clients endpoint (serveClients() in clients.go)

- /clients - responds with a list of current clients
- /clients/new - creates a new client
- DELETE /clients/{id} - deletes the client with ID: {id}
- GET /clients/{id} - responds with the client record

The /clients/ endpoints were first. The UI was added after and introduced it's own logic.

## Goal: Consolidate client changes to /client APIs

The goal is to update the UI to use /client/ endpoints instead of its own.

- Update the UI to use the client management API served under /clients
- Maintain the API contract of /clients
- keep the HTML templates (ui-edit.html, ui-list.html, ui-header.html) but have them use client side JS to interact with /clients/ endpoints
- Remove the code for handling IDPServer.funnelClient data mutations in ui.go
