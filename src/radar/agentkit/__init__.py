"""Read-only access to a deployed radar for agents: one client, a CLI, a stdio MCP server (roadmap R7).

Everything here reads the documents the publish station already writes (schemas/site-data.schema.json) through the
site's own gate. Nothing writes, nothing reaches the table, no new network surface: the MCP server speaks on stdio."""
