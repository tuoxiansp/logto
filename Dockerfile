# Build stage
FROM node:16-alpine as builder
WORKDIR /etc/logto
ENV CI=true

# No need for build
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true

# Install toolchain
RUN npm add --location=global pnpm@^7.14.0
# https://github.com/nodejs/docker-node/blob/main/docs/BestPractices.md#node-gyp-alpine
RUN apk add --no-cache python3 make g++

COPY . .

# Install dependencies and build
RUN pnpm i
RUN pnpm -r build

# Add official connectors
RUN pnpm cli connector add --official -p .

# Patch aliyun-connector-sms
COPY patches ./packages/core/connectors/@logto-connector-aliyun-sms/lib

# Prune dependencies for production
RUN rm -rf node_modules packages/**/node_modules
RUN NODE_ENV=production pnpm i

# Clean up
RUN rm -rf .parcel-cache pnpm-*.yaml

# Seal stage
FROM node:16-alpine as app
WORKDIR /etc/logto
COPY --from=builder /etc/logto .
EXPOSE 3001
ENTRYPOINT ["npm", "start"]
