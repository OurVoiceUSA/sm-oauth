
var fs = require('fs');
var keypair = require('keypair');

if (fs.existsSync("rsa.key")) {
  console.error("ERROR: rsa.key exists, not overwriting. Exiting!");
  process.exit(1);
}

console.log("Generating keypair for sm-oauth");
var pair = keypair();

fs.writeFileSync("rsa.key", pair.private);
fs.writeFileSync("rsa.pub", pair.public);

console.log("Written to rsa.key and rsa.pub");

