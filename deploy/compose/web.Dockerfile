FROM node:24-bookworm-slim AS builder
RUN npm install -g pnpm@11.26.0
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web/package.json apps/web/package.json
RUN pnpm install --frozen-lockfile
COPY apps/web apps/web
COPY fixtures fixtures
RUN pnpm --filter @mailent/web build

FROM nginx:1.28-alpine
COPY deploy/compose/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/apps/web/dist /usr/share/nginx/html
EXPOSE 80
