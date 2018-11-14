FROM node:carbon

RUN mkdir -p /app
WORKDIR /app

COPY .babelrc .
COPY package.json .
COPY package-lock.json .
RUN npm install
RUN mkdir /app/node_modules/.cache && chown node:node /app/node_modules/.cache
# fix dropbox oauth2 bug
RUN cp node_modules/passport-dropbox/lib/index.js node_modules/passport-dropbox-oauth2/lib/passport-dropbox-oauth2/index.js

COPY poke.js .
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s CMD node /app/poke.js
COPY server.js .

EXPOSE 8080
USER node

CMD [ "npm", "run", "docker" ]

