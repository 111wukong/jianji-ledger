FROM node:20-alpine
WORKDIR /app
COPY web ./web
ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0
ENV LEDGER_DATA_DIR=/app/data
VOLUME ["/app/data"]
EXPOSE 3000
CMD ["node", "web/server.mjs"]
