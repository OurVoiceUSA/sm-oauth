import redis from 'redis';

import { doExpressStartup } from './lib/express.js';

doExpressStartup(redis);
