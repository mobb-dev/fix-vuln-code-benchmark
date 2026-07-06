# Go toolchain plus the Claude and Codex CLIs, for running Go cases in a container.
FROM golang:1.26
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates curl && \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && rm -rf /var/lib/apt/lists/*
RUN npm install -g @anthropic-ai/claude-code && (npm install -g @openai/codex || echo "codex CLI skipped")
WORKDIR /work
