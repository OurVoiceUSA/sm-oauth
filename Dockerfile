FROM node:carbon

RUN mkdir -p /app
WORKDIR /app

COPY .babelrc .
COPY package.json .
COPY package-lock.json .
RUN npm install

COPY poke.js .
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s CMD node /app/poke.js
COPY server.js .

EXPOSE 8080
USER node

CMD [ "npm", "start" ]

