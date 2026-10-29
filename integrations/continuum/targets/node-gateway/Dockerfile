# Edge ingest gateway for partner telemetry (brotli-compressed batches)
FROM node:24.22.0-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY src/ ./src/
EXPOSE 8080
CMD ["node", "src/server.js"]
