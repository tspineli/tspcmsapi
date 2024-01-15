const { time, table } = require('console');
var express = require('express');
var router = express.Router();
const fs = require('fs');
const crypto = require('crypto');
const axios = require('axios');


router.get('/', async function(req, res, next) {

  const oauthtoken = 'Bearer ' + req.query.token;

  const certificate = fs.readFileSync('./cert.pem');
  const pkey = fs.readFileSync('./key.pem');

  var b64cert = certificate.toString().replace('-----BEGIN CERTIFICATE-----','')
  .replace('-----END CERTIFICATE-----','')
  .replace(/\r?\n|\r/g,'');


  let signhashsessioninfo = await axios.post('https://demo.docusign.net/restapi/v2.1/signature/signhashsessioninfo', {
    certificate: b64cert
  }, {
    headers: {
      'Authorization': oauthtoken, 
      'Content-Type': 'application/json'
    }
  }
)

const dochash = signhashsessioninfo.data.documents[0].data;
const docid = signhashsessioninfo.data.documents[0].documentId;


let signedattributesreq = await axios.post('https://sigadapter-d.docusign.net/api/cms/v1/signedattributes', {
  userCert: b64cert,
  hash: dochash,
  format: 'PADES'
}, {
  headers: {
    'Authorization': oauthtoken, 
    'Content-Type': 'application/json'
  }
}
)

const signedattributes = signedattributesreq.data.signedAttributes;

// Decode the base64 content
const content = Buffer.from(signedattributes, 'base64');

// Calculate the hash
const hash = crypto.createHash('sha256').update(content).digest();

  var id = Buffer.from([0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]);
  var allData = Buffer.concat([id, hash]);
  var signature = crypto.privateEncrypt(pkey, allData); // crypto.constants.RSA_PKCS1_PADDING by default

  let signatureb64 = signature.toString('base64');

  let cmsreq = await axios.post('https://sigadapter-d.docusign.net/api/cms/v1/cms', {
  userCert: b64cert,
  hash: dochash,
  format: 'PADES',
  signature: signatureb64,
  signedAttributes: signedattributes,
  TimestampToken: signedattributes
}, {
  headers: {
    'Authorization': oauthtoken, 
    'Content-Type': 'application/json'
  }
}
)

const cms = cmsreq.data.cms;
  
let completesignhash = await axios.post('https://demo.docusign.net/restapi/v2.1/signature/completesignhash', {
  documentUpdateInfos: [{
    documentId: docid,
    data: cms,
    returnFormat: 'CMS'
  }]
}, {
  headers: {
    'Authorization': oauthtoken, 
    'Content-Type': 'application/json'
  }
}
)


res.send(completesignhash.data);

});


module.exports = router;
