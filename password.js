const crypto = require('crypto'); 
//// https://www.geeksforgeeks.org/node-js-crypto-pbkdf2-method/
hashPassword = (password) =>{

    const derivedKey = crypto.pbkdf2Sync(password, 'salt', 100000, 64, 'sha512'); // originally i used pkbdf2 without Sync and had to use callback, but i took another look at the project and it seemed blocking the thread in this case isnt too bad :D
    return `${salt}:${derivedKey.toString('hex')}`;
  }

verifyPassword = (password, hash) => {
    const [salt, key] = hash.split(':'); // split the hash into salt and key
    const derivedKey = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex'); // carrying out the same operations on our inputted password as the original key
    return key === derivedKey; // compare the dervied key with the original key attached to the hash, if they match in content and datatype this returns a true. otherwise, false
}

module.exports = { hashPassword, verifyPassword };