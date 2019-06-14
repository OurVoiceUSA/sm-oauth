FROM node:dubnium-alpine as build

RUN apk update && apk upgrade && \
    apk add --no-cache git

RUN mkdir -p /app
WORKDIR /app

COPY .babelrc .
COPY package.json .
COPY package-lock.json .

RUN npm install

FROM node:dubnium-alpine

COPY --from=build /app /app
WORKDIR /app

# fix dropbox oauth2 bug
RUN cp node_modules/passport-dropbox/lib/index.js node_modules/passport-dropbox-oauth2/lib/passport-dropbox-oauth2/index.js

ENV NODE_ENV=production
ENV BABEL_CACHE_PATH=/tmp/.babel_cache
ENV NO_UPDATE_NOTIFIER=1

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s CMD node /app/poke.js
COPY lib lib
copy *.js ./

EXPOSE 8080
USER node

CMD [ "node", "node_modules/@babel/node/lib/_babel-node", "server.js" ]

