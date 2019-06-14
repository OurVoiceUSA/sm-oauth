## Introduction

This is the oauth server for our back-end services. It does social media authentication and returns a JWT signed by an RSA keypair.

## Development Setup

Start by configuring an `.env` file:

    cat << EOF > .env
    REDIS_HOST=localhost
    REDIS_PORT=6379
    WSBASE=http://localhost:8080
    OAUTH_FACEBOOK_CLIENTID=<YOUR ID>
    OAUTH_FACEBOOK_SECRET=<YOUR SECRET>
    OAUTH_GOOGLE_CLIENTID=<YOUR ID>
    OAUTH_GOOGLE_SECRET=<YOUR SECRET>
    OAUTH_DROPBOX_CLIENTID=<YOUR ID>
    OAUTH_DROPBOX_SECRET=<YOUR SECRET>
    TOKEN_DISCLAIMER="Link to your website terms of use here"
    JWT_PUB_KEY=./rsa.pub
    JWT_PRV_KEY=./rsa.key
    DEBUG=1
    EOF

**NOTE**: Not all the `OAUTH_` properties are required; the various oauth strategies only loaded if the config for them is set.

Then, run the following steps:

* Install dependencies: `npm install`
* Generate an RSA keypair: `npm run genkeys`
* Start the application: `npm start`

When deploying to production, be sure to properly protect your RSA keypair and OAUTH properties.

## Contributing

Thank you for your interest in contributing to us! To avoid potential legal headaches please sign our CLA (Contributors License Agreement). We handle this via pull request hooks on GitHub provided by https://cla-assistant.io/

## License

	Software License Agreement (AGPLv3+)

	Copyright (c) 2018, Our Voice USA. All rights reserved.

        This program is free software; you can redistribute it and/or
        modify it under the terms of the GNU Affero General Public License
        as published by the Free Software Foundation; either version 3
        of the License, or (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU Affero General Public License for more details.

        You should have received a copy of the GNU Affero General Public License
        along with this program; if not, write to the Free Software
        Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
