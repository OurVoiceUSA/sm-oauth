FROM node:dubnium-alpine

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

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s CMD node /app/poke.js
COPY lib lib
copy *.js ./

EXPOSE 8080
USER node

CMD [ "node", "node_modules/@babel/node/lib/_babel-node", "server.js" ]

