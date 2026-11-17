# gmail-multi-mcp

A small MCP server that gives Claude access to several Gmail accounts through one custom connector.
Runs on Google Cloud Run; account tokens live in Secret Manager; the MCP endpoint is served at a secret path.

- `/connect` signs in a Gmail account (allow-listed addresses only) and stores its refresh token.
- `/mcp/<secret>` is the Claude connector URL.

No credentials are stored in this repository.
