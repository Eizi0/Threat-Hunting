FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends nginx curl iproute2 python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY app/ ./
RUN npm install --no-audit --no-fund && npx next telemetry disable && npm run build
COPY nginx.conf /etc/nginx/nginx.conf
