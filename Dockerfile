# syntax=docker/dockerfile:1

########## deps ##########
FROM node:20.5.0-alpine AS deps
RUN apk add --no-cache bash openssl git python3 make g++
WORKDIR /app

COPY package.json yarn.lock ./
RUN corepack enable \
 && corepack prepare yarn@1.22.22 --activate \
 && yarn install --frozen-lockfile

########## build ##########
FROM node:20.5.0-alpine AS build
WORKDIR /app

COPY --from=deps /app/node_modules/ ./node_modules/
COPY . .

# Prisma client (needs DATABASE_URL)
ARG DATABASE_URL
ENV DATABASE_URL=${DATABASE_URL}
RUN npx prisma generate --schema=prisma/schema.prisma

RUN yarn build

########## runtime ##########
FROM node:20.5.0-alpine
WORKDIR /app
RUN adduser -u 10001 -D app

COPY --from=build /app /app
RUN chown -R app:app /app

USER app
ENV NODE_ENV=production PORT=3000
EXPOSE 3000
CMD ["node", "dist/app.js"]
