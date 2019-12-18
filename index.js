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
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on port ${port}...`));

//////////////////////////////////////////////////////////////////////////
// CHECK PWNED FOR PASSWORD BREACHES********

app.get('/api/checkpwned', async (req, res) => {
  const hash = crypto.createHash('sha1');
  hash.update(req.query.password);
  var hashedPassword = hash.digest('hex').toUpperCase();
  var prefix = hashedPassword.slice(0, 5);
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

// STORE NEW PASSWORD INFO ***********

app.post('/api/newpass', async (req, res) => {
  if (req.body.publicKey) {
    var encryptBool = true;
    var toEncrypt = req.body.password;
    var encryptBuffer = Buffer.from(toEncrypt);

    var encrypted = publicEncrypt(req.body.publicKey, encryptBuffer);
  } else {
    var encryptBool = false;
  }

  // get pwned password breaches
  const hash = crypto.createHash('sha1');
  hash.update(req.body.password);
  var hashedPassword = hash.digest('hex').toUpperCase();
  var prefix = hashedPassword.slice(0, 5);
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

  // get password strength

  var pass = req.body.password;
  var zxcvbnResult = zxcvbn(pass);
  var strengthScore = zxcvbnResult.score;
  if (encryptBool) {
    var obj = {
      passwordFor: req.body.passwordFor,
      usernameOrEmail: req.body.usernameOrEmail,
      password: encrypted,
      strength: strengthScore,
      pwnedInfo: breachRes,
      encrypted: encryptBool
    };
  } else {
    var obj = {
      passwordFor: req.body.passwordFor,
      usernameOrEmail: req.body.usernameOrEmail,
      password: req.body.password,
      strength: strengthScore,
      pwnedInfo: breachRes,
      encrypted: encryptBool
    };
  }
  var success = myCache.set(`${req.body.passwordFor}`, obj, 999999999);
  res.send(success);
});

// GET SINGLE PASSWORD INFO***************

app.get('/api/passinfo', (req, res) => {
  var storeKey = req.body.passwordFor;
  var value = myCache.get(storeKey);
  if (value == undefined) {
    console.log("Can't find password info");
  } else {
    var encrypted = value.password;
    if (req.body.privateKey) {
      if (value.encrypted) {
        var decryptBuffer = Buffer.from(encrypted.toString('base64'), 'base64');
        var priv = req.body.privateKey.toString();
        var decrypted = privateDecrypt(priv, decryptBuffer);
        value.password = decrypted.toString();
      }
    }
  }
  res.send(value);
});

// GET LIST OF ALL PASSWORDS INFO***********

app.get('/api/listpass', (req, res) => {
  var passArray = [];
  var mykeys = myCache.keys();
  mykeys.forEach(key => {
    var pass = myCache.get(key);
    if (req.body.privateKey) {
      if (pass.encrypted) {
        var encrypted = pass.password;
        var decryptBuffer = Buffer.from(encrypted.toString('base64'), 'base64');
        var priv = req.body.privateKey.toString();
        var decrypted = privateDecrypt(priv, decryptBuffer);
        pass.password = decrypted.toString();
      }
    }
    passArray.push(pass);
  });
  res.send(passArray);
});

// CHECK STRENGTH OF SINGLE PASSWORD*****

app.get('/api/strength', (req, res) => {
  var pass = req.query.password;
  var zxcvbnResult = zxcvbn(pass);
  var crackTimes = zxcvbnResult.crack_times_display;
  var strengthScore = zxcvbnResult.score;
  var strength = {
    score: strengthScore,
    crackTimes: crackTimes
  };
  res.send(200, strength);
});

// GENERATE PUBLIC/PRIVATE KEYS*********

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
  console.log(publicKey);
  console.log(privateKey);

  var keys = {
    public: publicKey,
    private: privateKey
  };
  res.send(keys);
});
