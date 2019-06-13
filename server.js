import redis from 'redis';

import { doExpressInit } from './lib/express';
import { ov_config } from './lib/ov_config';

const app = doExpressInit(redis);

// Launch the server
const server = app.listen(ov_config.server_port, () => {
  const { address, port } = server.address();
  console.log('sm-oauth express');
  console.log(`Listening at http://${address}:${port}`);
});
