# syntax=docker/dockerfile:1
FROM node:24-alpine
WORKDIR /app
COPY relay.mjs ./
USER node
EXPOSE 6514
CMD ["node", "relay.mjs"]
