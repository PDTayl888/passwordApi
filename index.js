var express = require('express');
var app = express();
var zxcvbn = require('zxcvbn');
var NodeCache = require('node-cache');
var myCache = new NodeCache();
var crypto = require('crypto');
const axios = require('axios');
const {
  generateKeyPairSync,
  publicEncrypt,
  privateDecrypt
} = require('crypto');

var cors = require('cors');
app.options('*', cors());
app.use(cors());
app.use(express.json());
// app.use(express.urlencoded());
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on port ${port}...`));

// ////////////////////////////////////////////////////////////////////////

app.get('/api/checkpwned', async (req, res) => {
  const hash = crypto.createHash('sha1');
  hash.update('red pony');
  var hashedPassword = hash.digest('hex').toUpperCase();
  console.log(hashedPassword);
  var prefix = hashedPassword.slice(0, 5);
  console.log(prefix);
  var pwnedApi = `https://api.pwnedpasswords.com/range/${prefix}`;

  var fullListOfHashes = '';
  var hashFinalResult = '';

  function getHashMatches() {
    return axios.get(pwnedApi);
  }

  var breachRes = await getHashMatches()
    .then(response => {
      fullListOfHashes = response.data;
    })
    .then(response => {
      var res = fullListOfHashes.split('\r\n').map(h => {
        var splitAtColon = h.split(':');
        return {
          hash: prefix + splitAtColon[0],
          count: parseInt(splitAtColon[1])
        };
      });

      var found = res.find(h => h.hash === hashedPassword);
      if (found) {
        hashFinalResult = `Found ${found.count} occurences of password breaches`;
      } else {
        hashFinalResult = 'No password breaches found';
        dataArray.push(hashFinalResult);
      }

      return hashFinalResult;
    })
    .catch(error => {
      console.log(error);
    });
  res.send(breachRes);
});

// ////////////////////////////////////////////////////////////////

app.post('/api/newpass', async (req, res) => {
  if (req.body.publicKey) {
    var encryptBool = true;
    var toEncrypt = req.body.password;
    var encryptBuffer = Buffer.from(toEncrypt);

    var encrypted = publicEncrypt(req.body.publicKey, encryptBuffer);
    console.log('ENCRYPTED', encrypted);
  } else {
    var encryptBool = false;
  }

  //////////////////////////////////////////////
  const hash = crypto.createHash('sha1');
  hash.update(req.body.password);
  var hashedPassword = hash.digest('hex').toUpperCase();
  console.log(hashedPassword);
  var prefix = hashedPassword.slice(0, 5);
  console.log(prefix);
  var pwnedApi = `https://api.pwnedpasswords.com/range/${prefix}`;

  var fullListOfHashes = '';
  var hashFinalResult = '';

  function getHashMatches() {
    return axios.get(pwnedApi);
  }

  var breachRes = await getHashMatches()
    .then(response => {
      fullListOfHashes = response.data;
    })
    .then(response => {
      var res = fullListOfHashes.split('\r\n').map(h => {
        var splitAtColon = h.split(':');
        return {
          hash: prefix + splitAtColon[0],
          count: parseInt(splitAtColon[1])
        };
      });

      var found = res.find(h => h.hash === hashedPassword);
      if (found) {
        hashFinalResult = `Found ${found.count} occurences of password breaches`;
      } else {
        hashFinalResult = 'No password breaches found';
      }

      return hashFinalResult;
    })
    .catch(error => {
      console.log(error);
    });
  ///////////////////////////////////////////////////
  var pass = req.body.password;
  var zxcvbnResult = zxcvbn(pass);
  var strengthScore = zxcvbnResult.score;
  console.log('STRENGTH SCORE', strengthScore);

  ///////////////////////////////////////////////////

  var obj = {
    passwordFor: req.body.passwordFor,
    usernameOrEmail: req.body.usernameOrEmail,
    password: encrypted,
    strength: strengthScore,
    pwnedInfo: breachRes,
    encrypted: encryptBool
  };
  console.log('OBJ', obj);
  var success = myCache.set(`${req.body.passwordFor}`, obj, 999999999);
  console.log('SUCCESS', success);
  console.log('NEW PASS SUCCESS');
  res.send(success);
});

app.get('/api/passinfo', (req, res) => {
  console.log('PASS INFO PASSWORDFOR', req.body.passwordFor);
  var storeKey = req.body.passwordFor;
  var value = myCache.get(storeKey);
  if (value == undefined) {
    console.log("CAN'T FIND IT YALLL!!!");
  } else {
    var encrypted = value.password;
    if (value.encrypted) {
      var decryptBuffer = Buffer.from(encrypted.toString('base64'), 'base64');
      console.log(decryptBuffer);
      var priv = req.body.privateKey.toString();
      var decrypted = privateDecrypt(priv, decryptBuffer);
      console.log(decrypted);
      value.password = decrypted.toString();
    }
  }
  res.send(value);
});

app.get('/api/listpass', (req, res) => {
  var passArray = [];
  var mykeys = myCache.keys();
  mykeys.forEach(key => {
    var pass = myCache.get(key);
    if (pass.encrypted) {
      var encrypted = pass.password;
      var decryptBuffer = Buffer.from(encrypted.toString('base64'), 'base64');
      console.log(decryptBuffer);
      var priv = req.body.privateKey.toString();
      var decrypted = privateDecrypt(priv, decryptBuffer);
      console.log(decrypted);
      pass.password = decrypted.toString();
    }
    passArray.push(pass);
  });
  console.log(passArray);
  console.log(mykeys);
  res.send(passArray);
});

app.get('/api/strength', (req, res) => {
  console.log('strength route activated');
  var pass = 'gary panda deer lambda';
  var zxcvbnResult = zxcvbn(pass);
  var strengthScore = zxcvbnResult.score;
  console.log(strengthScore);
  res.send(200, strengthScore);
});

app.get('/api/genKeys', (req, res) => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  // print out the generated keys
  console.log(`PublicKey: ${publicKey}`);
  console.log(`PrivateKey: ${privateKey}`);

  //message to be encrypted
  var toEncrypt = 'red pony yellow giraffe boat';
  var encryptBuffer = Buffer.from(toEncrypt);

  //encrypt using public key
  var encrypted = publicEncrypt(publicKey, encryptBuffer);

  //print out the text and cyphertext
  console.log('Text to be encrypted:');
  console.log(toEncrypt);
  console.log('cipherText:');
  console.log(encrypted.toString());

  //decrypt the cyphertext using the private key
  var decryptBuffer = Buffer.from(encrypted.toString('base64'), 'base64');
  var decrypted = privateDecrypt(privateKey, decryptBuffer);

  //print out the decrypted text
  console.log('decrypted Text:');
  console.log(decrypted.toString());

  var keys = {
    public: publicKey,
    private: privateKey
  };
  console.log(keys.public);
  res.send(keys.public);
});
