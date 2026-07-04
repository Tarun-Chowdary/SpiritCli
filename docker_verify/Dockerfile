FROM node:14.17.0-alpine

ENV DB_PASSWORD=hunter2

RUN apk add --no-cache openssl=3.1.4-r0

COPY . /app
CMD ["node", "app.js"]
