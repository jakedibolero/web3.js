/* eslint-env worker */
const keccak = require('keccak');
const randomBytes = require('randombytes');
const CryptoJS = require('crypto-js')
let bls_ = require('./bls');
const v4 = require('uuid').v4;
const rlp = require('rlp')
const step = 500;

const  DefaultDataDirName = "petrichor";

/**
 * Transform a private key into an address
 */ 
const privateToPublic = secretBytes => bls_.BonehLynnShacham.generatePublicKey(secretBytes);
const privateToAddress = p => keccak('keccak256').update(Buffer.from(p)).digest('hex').slice(-40);

const signMessage = (hashMessage, secretBytes) => bls_.BonehLynnShacham.sign(hashMessage, secretBytes);

const verifyMessage = (publicKeyG2, hashedMessage, signedHashedMessageG1) => bls_.BonehLynnShacham.verify(publicKeyG2, hashedMessage, signedHashedMessageG1);


function download(data, strFileName, strMimeType) {

    var self = window, // this script is only for browsers anyway...
        defaultMime = "application/octet-stream", // this default mime also triggers iframe downloads
        mimeType = strMimeType || defaultMime,
        payload = data,
        url = !strFileName && !strMimeType && payload,
        anchor = document.createElement("a"),
        toString = function(a){return String(a);},
        myBlob = (self.Blob || self.MozBlob || self.WebKitBlob || toString),
        fileName = strFileName || "download",
        blob,
        reader;
        myBlob= myBlob.call ? myBlob.bind(self) : Blob ;

    if(String(this)==="true"){ //reverse arguments, allowing download.bind(true, "text/xml", "export.xml") to act as a callback
        payload=[payload, mimeType];
        mimeType=payload[0];
        payload=payload[1];
    }


    if(url && url.length< 2048){ // if no filename and no mime, assume a url was passed as the only argument
        fileName = url.split("/").pop().split("?")[0];
        anchor.href = url; // assign href prop to temp anchor
          if(anchor.href.indexOf(url) !== -1){ // if the browser determines that it's a potentially valid url path:
            var ajax=new XMLHttpRequest();
            ajax.open( "GET", url, true);
            ajax.responseType = 'blob';
            ajax.onload= function(e){ 
              download(e.target.response, fileName, defaultMime);
            };
            setTimeout(function(){ ajax.send();}, 0); // allows setting custom ajax headers using the return:
            return ajax;
        } // end if valid url?
    } // end if url?


    //go ahead and download dataURLs right away
    if(/^data:([\w+-]+\/[\w+.-]+)?[,;]/.test(payload)){

        if(payload.length > (1024*1024*1.999) && myBlob !== toString ){
            payload=dataUrlToBlob(payload);
            mimeType=payload.type || defaultMime;
        }else{			
            return navigator.msSaveBlob ?  // IE10 can't do a[download], only Blobs:
                navigator.msSaveBlob(dataUrlToBlob(payload), fileName) :
                saver(payload) ; // everyone else can save dataURLs un-processed
        }

    }else{//not data url, is it a string with special needs?
        if(/([\x80-\xff])/.test(payload)){			  
            var i=0, tempUiArr= new Uint8Array(payload.length), mx=tempUiArr.length;
            for(i;i<mx;++i) tempUiArr[i]= payload.charCodeAt(i);
             payload=new myBlob([tempUiArr], {type: mimeType});
        }		  
    }
    blob = payload instanceof myBlob ?
        payload :
        new myBlob([payload], {type: mimeType}) ;


    function dataUrlToBlob(strUrl) {
        var parts= strUrl.split(/[:;,]/),
        type= parts[1],
        decoder= parts[2] == "base64" ? atob : decodeURIComponent,
        binData= decoder( parts.pop() ),
        mx= binData.length,
        i= 0,
        uiArr= new Uint8Array(mx);

        for(i;i<mx;++i) uiArr[i]= binData.charCodeAt(i);

        return new myBlob([uiArr], {type: type});
     }

    function saver(url, winMode){

        if ('download' in anchor) { //html5 A[download]
            anchor.href = url;
            anchor.setAttribute("download", fileName);
            anchor.className = "download-js-link";
            anchor.innerHTML = "downloading...";
            anchor.style.display = "none";
            document.body.appendChild(anchor);
            setTimeout(function() {
                anchor.click();
                document.body.removeChild(anchor);
                if(winMode===true){setTimeout(function(){ self.URL.revokeObjectURL(anchor.href);}, 250 );}
            }, 66);
            return true;
        }

        // handle non-a[download] safari as best we can:
        if(/(Version)\/(\d+)\.(\d+)(?:\.(\d+))?.*Safari\//.test(navigator.userAgent)) {
            if(/^data:/.test(url))	url="data:"+url.replace(/^data:([\w\/\-\+]+)/, defaultMime);
            if(!window.open(url)){ // popup blocked, offer direct download:
                if(confirm("Displaying New Document\n\nUse Save As... to download, then click back to return to this page.")){ location.href=url; }
            }
            return true;
        }

        //do iframe dataURL download (old ch+FF):
        var f = document.createElement("iframe");
        document.body.appendChild(f);

        if(!winMode && /^data:/.test(url)){ // force a mime that will download:
            url="data:"+url.replace(/^data:([\w\/\-\+]+)/, defaultMime);
        }
        f.src=url;
        setTimeout(function(){ document.body.removeChild(f); }, 333);

    }//end saver




    if (navigator.msSaveBlob) { // IE10+ : (has Blob, but not a[download] or URL)
        return navigator.msSaveBlob(blob, fileName);
    }

    if(self.URL){ // simple fast and modern way using Blob and URL:
        saver(self.URL.createObjectURL(blob), true);
    }else{
        // handle non-Blob()+non-URL browsers:
        if(typeof blob === "string" || blob.constructor===toString ){
            try{
                return saver( "data:" +  mimeType   + ";base64,"  +  self.btoa(blob)  );
            }catch(y){
                return saver( "data:" +  mimeType   + "," + encodeURIComponent(blob)  );
            }
        }

        // Blob but not URL support:
        reader=new FileReader();
        reader.onload=function(e){
            saver(this.result);
        };
        reader.readAsDataURL(blob);
    }
    return true;
};

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
    let wallet;
    if (password) {
            wallet = generateWallet(privateKey, password, address);
            const fileName = 'UTC--' + new Date().toISOString().replace(/:/g, '-') + '--' + address;
            download(JSON.stringify(wallet), fileName, 'application/octet-stream');
            returnSignal[0] = false;
        }
        return wallet;
}

function toAddress(pub) {
    if(!pub) return false;
    return keccak('keccak256').update(Buffer.from(pub)).digest().slice(-20);

}

const hashComplete = (pub, hash) => {
    const prefixBytes = Buffer.from(DefaultDataDirName);
    const pubBytes = Buffer.from(pub.s);
    const arrayBytes = [prefixBytes, pubBytes, hash];
    const concatedBytes = Buffer.concat(arrayBytes);

    return keccak('keccak256').update(concatedBytes).digest();;

}

function rlpMessage(arguments){
    return rlp.encode(arguments).toString('hex')
}

const signMsg = async (messageRLP, secretBytes) =>  {
    try {
        let hashedMessage = keccak('keccak256').update(messageRLP).digest();
        let pub = privateToPublic(secretBytes);
        hashedMessage = hashComplete(pub, hashedMessage);
        let signed  = signMessage(hashedMessage, secretBytes);
        return {
            "signed": signed.s,
            "pubKey": pub,
            "hashed": hashedMessage
        };
    } catch(err) {
        console.error("Error from signing Message" + err);
    }


}

async function signTx(transaction, secretBytes) {
    let arguments = [transaction.nonce,transaction.gasPrice,transaction.gas,transaction.to,transaction.value,undefined,[]];
    let rlped = rlpMessage(arguments);
    let signed = await signMsg(rlped, secretBytes);

    
    arguments[arguments.length - 1][0] = '0x' + Buffer.from(signed.signed).toString('hex')
    arguments[arguments.length - 1][1] = '0x' + Buffer.from(signed.pubKey.s).toString('hex')
    return rlpMessage(arguments);
}

/**
 *      
 * @param {Buffer} secret 
 * @param {String} message 
 * @returns Object{Uint8Array, Hex}
 */
const sign = async(privateKey, transaction) =>  {
    try {
        return await signTx(transaction,Buffer.from(privateKey,"hex"));
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
    decryptPrivateKey,
    generateWallet,
    download,
    signTx
};
