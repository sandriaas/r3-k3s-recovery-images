FROM node:22-slim

ENV NODE_ENV=production
ENV PORT=8080

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts

COPY --chown=node:node src ./src

USER node
EXPOSE 8080

CMD ["node", "src/server.mjs"]
