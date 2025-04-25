const crypto = require('crypto');

// these are encoders and decoders from stackoverflow / geeksforgeeks.
function base64url(input) {
    return Buffer.from(input).toString('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
}

function base64urlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return Buffer.from(str, 'base64').toString();
}
  
const Jsonator = (payload, secret, exp = 3600) => {
    payload.exp = Math.floor(Date.now() / 1000) + exp; // adding the exp field to the json payload
    const head = base64url(JSON.stringify({alg:'HS256',typ:'JWT'})); // the header standards mentioned in the document
    const body = base64url(JSON.stringify(payload)); // stringfying the payload and encoding it based on the jwt standard
    // the hmac function consumed an algorithm and a key to encode any given data
    // the update function adds data into the newly created hmac object, we only have one instance of streamed data the head and body 
    // but this can also be used to feed a stream if we keep this open
    // after we're done feeding our hmac object we call digest to consume the hmac object making turning it 
    // into the format we want and making sure this object can no longer be updated or digested again.
    // the digest function takes in a string format, in this case we want to use base64url so we can use it in our token
    const sig = base64url(crypto.createHmac('sha256', secret).update(`${head}.${body}`).digest());    // this is used to verify the body and head, it is always at the end 
                                                                                                    // to follow the standards of head.payload.sig this allows for clean verification
    return `${head}.${body}.${sig}`;
};
  
const Jsonizer = (token, secret) => {
    // here we parse the token into header payload and sig just like we organized  them
    const [h, p, s] = token.split('.');
    // here we're trying to create a new signature based on the payload and header using the secret key we used to encode the first one
    // if they match we know that this script made the token. this is the exact same approach we took while dealing with hashed passwords in the other file.
    const validSig = base64url(crypto.createHmac('sha256', secret).update(`${h}.${p}`).digest());
    if (s !== validSig) throw 'this signature doesnt match our key';
    // if the signature is valid we know that decoding the payload is safe and also will give us relevant data to out app.
    const data = JSON.parse(base64urlDecode(p));
    // making sure our token is not expired and the data inside can still be used
    if (data.exp && Date.now() / 1000 > data.exp) throw 'expired token';
    return data;
};

module.exports = { Jsonator, Jsonizer };