FROM node:22.11-alpine3.20 AS deps
WORKDIR /app
RUN apk add --no-cache curl && corepack enable
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

FROM node:22.11-alpine3.20 AS build
WORKDIR /app
RUN corepack enable
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN pnpm build && pnpm prune --prod

FROM node:22.11-alpine3.20 AS runner
WORKDIR /app
ENV NODE_ENV=production
ARG DATABASE_URL
ARG BETTER_AUTH_SECRET
ARG STRIPE_SECRET_KEY
ENV DATABASE_URL=$DATABASE_URL \
    BETTER_AUTH_SECRET=$BETTER_AUTH_SECRET \
    STRIPE_SECRET_KEY=$STRIPE_SECRET_KEY
COPY --from=build --chown=node:node /app/package.json ./package.json
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/.next ./.next
USER node
EXPOSE 3000
CMD ["node_modules/.bin/next", "start"]
