# Java toolchain (Maven, JDK 21) plus the Claude and Codex CLIs, for running Java cases in a container.
FROM maven:3.9-eclipse-temurin-21
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates curl && \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && rm -rf /var/lib/apt/lists/*
RUN npm install -g @anthropic-ai/claude-code && (npm install -g @openai/codex || echo "codex CLI skipped")
WORKDIR /work
