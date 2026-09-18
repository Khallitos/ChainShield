# Typosquat lab, collector UI + ingest API (no npm registry).
FROM node:20-alpine
WORKDIR /app
COPY collector/server.mjs ./collector/server.mjs
COPY website ./website
EXPOSE 5055
ENV DOCKER=1
ENV LISTEN_HOST=0.0.0.0
ENV DEMO_COLLECTOR_PORT=5055
CMD ["node", "collector/server.mjs"]
