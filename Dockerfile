FROM node:lts as build-server

RUN mkdir -p /app
WORKDIR /app

COPY .babelrc .
COPY package.json .
COPY package-lock.json .

RUN npm ci

FROM node:lts as build-client

COPY otp-sms/package.json /otp-sms/package.json
COPY otp-sms/package-lock.json /otp-sms/package-lock.json
RUN cd /otp-sms && npm ci
COPY otp-sms /otp-sms
RUN cd /otp-sms && CI=true npm test
RUN cd /otp-sms && npm run build

FROM node:lts-alpine

COPY --from=build-server /app /app
COPY --from=build-client /otp-sms/build /app/otp-sms
WORKDIR /app

ENV NODE_ENV=production
ENV BABEL_CACHE_PATH=/tmp/.babel_cache
ENV NO_UPDATE_NOTIFIER=1

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s CMD node /app/poke.js
COPY lib lib
copy *.js ./

EXPOSE 8080
USER node

CMD [ "node", "node_modules/@babel/node/lib/_babel-node", "server.js" ]

