FROM node:22-alpine

WORKDIR /app

# Keine externen npm-Pakete erforderlich (nutzt Node.js Standardbibliothek)
COPY index.html ./
COPY server.js ./

# Verzeichnis für Daten / Einreichungen
RUN mkdir -p /app/data

ENV PORT=3000
ENV NODE_ENV=production

EXPOSE 3000

CMD ["node", "server.js"]
