FROM docker.io/node:lts-alpine
LABEL maintainer="Lyas Spiehler"

RUN apk add --no-cache --upgrade git

RUN mkdir -p /var/node

WORKDIR /var/node

ARG CACHE_DATE=2024-09-16

RUN git clone https://github.com/lspiehler/cisco-nat-exporter.git

WORKDIR /var/node/cisco-nat-exporter

RUN npm install

EXPOSE 3000/tcp

CMD ["npm", "start"]