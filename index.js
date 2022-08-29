var CryptoJS = require("crypto-js");

function AESEncrypt(text, secretkey) {
  var cipherText = CryptoJS.AES.encrypt(text, secretkey).toString();
  return cipherText;
}

function AESDecrypt(cipherText, secretkey) {
  var bytes = CryptoJS.AES.decrypt(cipherText, secretkey);
  var originalText = bytes.toString(CryptoJS.enc.Utf8);
  return originalText;
}

module.exports.AESEncrypt = AESEncrypt;
module.exports.AESDecrypt = AESDecrypt;
