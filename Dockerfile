FROM node:20-alpine
WORKDIR /app
COPY web ./web
ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000
CMD ["node", "web/server.mjs"]
