FROM node:carbon-alpine

RUN mkdir -p /app
WORKDIR /app

ENV NODE_ENV=production
ENV BABEL_CACHE_PATH=/tmp/.babel_cache
ENV NO_UPDATE_NOTIFIER=1

COPY .babelrc .
COPY package.json .
COPY package-lock.json .

RUN npm install
# fix dropbox oauth2 bug
RUN cp node_modules/passport-dropbox/lib/index.js node_modules/passport-dropbox-oauth2/lib/passport-dropbox-oauth2/index.js

COPY poke.js .
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s CMD node /app/poke.js
COPY server.js .

# scrub busybox and npm
RUN rm -rf /bin/busybox /usr/local/lib/node_modules/

EXPOSE 8080
USER node

CMD [ "node", "node_modules/.bin/babel-node", "server.js" ]

