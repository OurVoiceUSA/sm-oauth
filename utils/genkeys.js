
var fs = require('fs');
var keypair = require('keypair');

console.log("Generating keypair for sm-oauth");
var pair = keypair();

fs.writeFileSync("rsa.key", pair.private);
fs.writeFileSync("rsa.pub", pair.public);

console.log("Written to rsa.key and rsa.pub");

