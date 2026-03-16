FROM node:22-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --production

COPY server.js upload.html ./

RUN mkdir -p /tmp/uploads && apk add --no-cache curl

ENV PORT=3000
EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

CMD ["node", "server.js"]
