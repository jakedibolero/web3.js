/* eslint-env worker */
const keccak = require('keccak');
const randomBytes = require('randombytes');
const CryptoJS = require('crypto-js')
let bls_ = require('./bls/bls');

const step = 500;

const  DefaultDataDirName = "petrichor";

/**
 * Transform a private key into an address
 */ 
const privateToPublic = secretBytes => bls_.BonehLynnShacham.generatePublicKey(secretBytes);
const privateToAddress = p => keccak('keccak256').update(Buffer.from(p)).digest('hex').slice(-40);

const signMessage = (hashMessage, secretBytes) => bls_.BonehLynnShacham.sign(hashMessage, secretBytes);

const verifyMessage = (publicKeyG2, hashedMessage, signedHashedMessageG1) => bls_.BonehLynnShacham.verify(publicKeyG2, hashedMessage, signedHashedMessageG1);


function getAddressFirstByte(pub) {
    let firstByte = keccak('keccak256').update(Buffer.from(pub)).digest().slice(-20)[0];
    return firstByte;
}
/**
 * Create a wallet from a random private key
 * @returns {{address: string, privKey: string}}
 */

 const getWalletFromPrivateKey = async (privateKey) => {
  let X = 0;
  let pub;
  try {
      await bls_.ensureReady();
      
      pub = privateToPublic(new Buffer(privateKey,"hex"));
      return {
          address: privateToAddress(pub.s),
          privKey: privateKey
      };

  } catch(err) {
      console.log("Error from init" + err);
  }

};
const getRandomWallet = async () => {
  let randbytes, X = 0;
  let pub;
  randbytes = randomBytes(32);
  try {
      await bls_.ensureReady();
      pub = privateToPublic(randbytes);
      while (!pub.isValid()) {
          randbytes = keccak('keccak256').update(randbytes).digest();
          pub = privateToPublic(randbytes);
          console.log(`Attempt ${X}`); X = X + 1;
      }

      return {
          address: privateToAddress(pub.s),
          privKey: randbytes.toString('hex')
      };

  } catch(err) {
      console.log("Error from init" + err);
  }
};


/**
 * Check if a wallet respects the input constraints
 * @param address
 * @param input
 * @param isChecksum
 * @param isSuffix
 * @returns {boolean}
 */


const toChecksumAddress = (address) => {
    const hash = keccak('keccak256').update(address).digest().toString('hex');
    let ret = '';
    for (let i = 0; i < address.length; i++) {
        ret += parseInt(hash[i], 16) >= 8 ? address[i].toUpperCase() : address[i];
    }
    return ret;
};

/**
 * Generate a lot of wallets until one satisfies the input constraints
 * @param input - String chosen by the user
 * @param isChecksum - Is the input case-sensitive
 * @param isSuffix - Is it a suffix, or a prefix
 * @param cb - Callback called after x attempts, or when an address if found
 * @returns
 */
const getVanityWalletPrivate = async (privateKey) => {
    //input = isChecksum ? input : input.toLowerCase();
    let wallet = await getWalletFromPrivateKey(privateKey);
    //cb({address: '0x' + toChecksumAddress(wallet.address), privKey: wallet.privKey, attempts});
    return {address: '0x' + toChecksumAddress(wallet.address), privateKey: wallet.privKey};
};
const getVanityWalletRandom = async () => {
  //input = isChecksum ? input : input.toLowerCase();
  let wallet = await getRandomWallet();
  //cb({address: '0x' + toChecksumAddress(wallet.address), privKey: wallet.privKey, attempts});
  return {address: '0x' + toChecksumAddress(wallet.address), privateKey: wallet.privKey};
};

/*
onmessage = function (event) {
    const input = event.data;
    try {
        getVanityWallet(input.hex, input.checksum, input.suffix, (message) => postMessage(message));
    } catch (err) {
        self.postMessage({error: err.toString()});
    }
};

module.exports = {
    onmessage
};

*/


function sliceWordArray(wordArray, start, end) {
    const newArray = wordArray.clone();
    newArray.words = newArray.words.slice(start, end);
    newArray.sigBytes = (end - start) * 4;
    return newArray;
}

function encryptPrivateKey(privateKey, password) {
    const iv = CryptoJS.lib.WordArray.random(16);
    const salt = CryptoJS.lib.WordArray.random(32);
    const key = CryptoJS.PBKDF2(password, salt, { // eslint-disable-line new-cap
        keySize: 8,
        hasher: CryptoJS.algo.SHA256,
        iterations: 262144
    });
    const cipher = CryptoJS.AES.encrypt(
        CryptoJS.enc.Hex.parse(privateKey),
        sliceWordArray(key, 0, 4),
        {
            iv: iv,
            mode: CryptoJS.mode.CTR,
            padding: CryptoJS.pad.NoPadding
        }
    );
    // eslint-disable-next-line new-cap
    const mac = CryptoJS.SHA3(sliceWordArray(key, 4, 8).concat(cipher.ciphertext), {
        outputLength: 256
    });

    return {
        kdf: 'pbkdf2',
        kdfparams: {c: 262144, dklen: 32, prf: 'hmac-sha256', salt: salt.toString()},
        cipher: 'aes-128-ctr',
        ciphertext: cipher.ciphertext.toString(),
        cipherparams: {iv: iv.toString()},
        mac: mac.toString()
    };
}
function decryptPrivateKey(cipherparams,ciphertext,password,salt){
  const key = CryptoJS.PBKDF2(password, CryptoJS.enc.Hex.parse(salt), { // eslint-disable-line new-cap
    keySize: 8,
    hasher: CryptoJS.algo.SHA256,
    iterations: 262144
});
  const decrypted = CryptoJS.AES.decrypt(
    {ciphertext:CryptoJS.enc.Hex.parse(ciphertext)}
    ,sliceWordArray(key, 0, 4),
    {
      iv: CryptoJS.enc.Hex.parse(cipherparams.iv),
      mode: CryptoJS.mode.CTR,
      padding: CryptoJS.pad.NoPadding
    }
);
return decrypted.toString();
}

// Generate a JSON wallet from a private key and a password
function generateWallet(privateKey, password, address) {
    return {
        address: address,
        crypto: encryptPrivateKey(privateKey, password),
        id: v4(),
        version: 3
    };
}

function save(address, privateKey, password , returnSignal) {
    if (password) {

        setTimeout(() => {
            const wallet = generateWallet(privateKey, password, address);
            const fileName = 'UTC--' + new Date().toISOString().replace(/:/g, '-') + '--' + address;
            download(JSON.stringify(wallet), fileName, 'application/json');
            returnSignal[0] = false;
        }, 20);
        return true;
    }
    
}

function toAddress(pub) {
    if(!pub) return false;
    return keccak('keccak256').update(Buffer.from(pub)).digest().slice(-20);

}

const hashComplete = (pub, hash) => {
    const hash1 = keccak('keccak256').update(DefaultDataDirName);
    const hash2 = hash1._clone();
    const hash3 = hash2.update(Buffer.from(pub.s));
    const hash4 = hash3._clone();

    return hash4.update(hash).digest();

}

/**
 * 
 * @param {Buffer} secret 
 * @param {String} message 
 * @returns Object{Uint8Array, Hex}
 */
const sign = async(secret, message) =>  {
    try {
        await bls_.ensureReady();
        let hashedMessage = keccak('keccak256').update(message).digest();
        const pub = privateToPublic(secret);
        hashedMessage = hashComplete(pub, hashedMessage);
    
        let signed  = signMessage(hashedMessage, secret);
        console.log(Buffer.from(signed.s).toString('hex'));
        return {signedBytes: signed.s, signedHex: Buffer.from(signed.s).toString('hex')};

    } catch(err) {
        console.log("Error from signing Message" + err);
    }
}

/**
 * 
 * @param {Buffer} secret 
 * @param {Uint8Array|Buffer} signedMessage 
 * @param {String} message 
 * @returns Boolean
 */
const verify = async(secret, signedMessage, message) =>  {
    try {
        await bls_.ensureReady();
        let hashedMessage = keccak('keccak256').update(message).digest();
        const pub = privateToPublic(secret);
        hashedMessage = hashComplete(pub, hashedMessage);

        let verified  = verifyMessage(pub, hashedMessage, signedMessage);
        console.log(verified);
        return verified;

    } catch(err) {
        console.log("Error from verifying Message" + err);
    }
}

const wallet = () => getRandomWallet();

module.exports = {
    getRandomWallet,
    wallet,
    sign,
    verify,
    getVanityWalletPrivate,
    getVanityWalletRandom,
    save,
    getRandomWallet,
    privateToPublic,
    decryptPrivateKey
};
