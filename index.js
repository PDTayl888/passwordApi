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
    var toEncrypt = req.body.pasword;
    var encryptBuffer = Buffer.from(toEncrypt);

    var encrypted = publicEncrypt(publicKey, encryptBuffer);
    console.log('ENCRYPTED', encrypted);
  } else {
    var encryptBool = false;
  }

  //////////////////////////////////////////////
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
  console.log(req.body.passwordFor);
  var success = myCache.set(`${req.body.passwordFor}`, obj, 999999999);
  res.send(success);
});

app.get('/api/passinfo', (req, res) => {
  var value = myCache.get(req.body.passwordFor);
  if (value == undefined) {
    console.log("CAN'T FIND IT YALLL!!!");
  } else {
    if (value.encrypted) {
      var decryptBuffer = Buffer.from(
        value.password.toString('base64'),
        'base64'
      );
      var decrypted = privateDecrypt(privateKey, decryptBuffer);
      value.password = decrypted;
    }
  }
  res.send(value);
});

app.get('/api/listpass', (req, res) => {
  var mykeys = myCache.keys();

  console.log(mykeys);
  res.send(mykeys);
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
  //   console.log('Text to be encrypted:');
  //   console.log(toEncrypt);
  //   console.log('cipherText:');
  //   console.log(encrypted.toString());

  //decrypt the cyphertext using the private key
  var decryptBuffer = Buffer.from(encrypted.toString('base64'), 'base64');
  var decrypted = privateDecrypt(privateKey, decryptBuffer);

  //print out the decrypted text
  //   console.log('decrypted Text:');
  //   console.log(decrypted.toString());

  var keys = {
    public: publicKey,
    private: privateKey
  };
  console.log(keys.public);
  res.send(keys.public);
});

// {
//     "publicKey": "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApVnq1OXj13054x\/cfAaK\r\nKBXudKdGMlMgAGHFfrZ49Af7j4y7+VoOSGkupL\/GSptEJSLSj\/FdhD4TTvUyKW9A\r\nWl88Q2v6zSKBs74ojOf4MX\/VQntHdOP8fgG0+q+Zc5OgEwGDqG60kj7O9XDPMvWZ\r\nNASixGs2OIHKfBucqrvhYSUSGdEVWlDVsH3R7XQ6hnN8caEiWOXUKgKK0LlGQE1O\r\nj0QGS\/GWVwmXFKeNOY\/D976xD9vINRhESDl5Gd\/21BaR6B88Pju3+609RBgo8BtQ\r\nPk5+VY4uvdXYMfdfR9paqInd4o6gXedMJQ+nczoextBEhLsQDA9T57KKygKxAj9D\r\nEyDrXXBCqdOoDc9OQXcwW2OYgdOr+BCYiv6lI\/vxekF0AazNicvdkZHaAM1oCh31\r\nZgRFNvWFuHjrzSGXYq0fZHbM3EdZAg4Sy0XhYNhA6+2tO+gpvP+VJIiyn30AVcXp\r\nm3fdtYx36RGax28wsbtP1Q2zY6H9V+yLuhe8LlMrW9z2JLHRAIHl1SFnMhD4iifF\r\n6PSGih32CbZH8LtobExSGbELZTCiuBMgC4z9DFPN7Ax7ip99ilfuTeHTKO5BWmWJ\r\nYhXYMakmt6rQsqLmlQh5L1pxyQN3zoeNmcMN7RGepF\/OO6PpTAIAI9xtUBSiDsSb\r\n4J3Nn5VRTZjXRdohHShv\/D8CAwEAAQ==",
//    "passwordFor": "Google",
//    "usernameOrEmail": "pdtay888",
//    "password": "beachbumhonolulu"
//  }

// {
//     "passwordFor": "Google",
//     "encrypted": "true"
//   }
