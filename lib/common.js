
import { get } from 'docker-secrets-nodejs';

export var getConfig = function (item, required, def) {
  let value = get(item);
  if (!value) {
    if (required) {
      let msg = "Missing config: "+item.toUpperCase();
      console.log(msg);
      throw msg;
    } else {
      return def;
    }
  }
  return value;
}

