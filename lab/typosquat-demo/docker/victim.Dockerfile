# Typosquat lab, fake "internal app" that runs npm install (file: deps only, no npm publish).
FROM node:20-bookworm-slim
WORKDIR /app
COPY packages ./packages
COPY victim-site ./victim-site
WORKDIR /app/victim-site
ENV DEMO_COLLECTOR_HOST=collector
ENV DEMO_COLLECTOR_PORT=5055
ENV DEMO_SECRET=sk-demo-set-in-compose
CMD ["npm", "install"]
