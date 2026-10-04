FROM node:22-bookworm@sha256:17b7fd60fd812617654c64b95f9b2dde94f103313073b672bc40fdad6dccbaa2 AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

FROM node:22-bookworm@sha256:17b7fd60fd812617654c64b95f9b2dde94f103313073b672bc40fdad6dccbaa2
WORKDIR /app
ENV NODE_ENV=production
COPY --from=dependencies --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json cli.mjs interactive.mjs local.mjs dmarc.mjs transport.mjs ./
USER node
# No listener, exposed port, writable config, credential file or background service.
# A private JSON envelope arrives through stdin; safe bounded results leave stdout.
ENTRYPOINT ["node", "cli.mjs"]
