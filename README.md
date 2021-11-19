![Build](https://github.com/m0rtadelo/ntlm-client/actions/workflows/pages.yml/badge.svg)
[![Known Vulnerabilities](https://snyk.io//test/github/m0rtadelo/ntlm-client/badge.svg?targetFile=package.json)](https://snyk.io//test/github/m0rtadelo/ntlm-client?targetFile=package.json)
![GitHub top language](https://img.shields.io/github/languages/top/m0rtadelo/ntlm-client.svg)
[![npm version](https://badge.fury.io/js/node-client-ntlm.svg)](https://badge.fury.io/js/node-client-ntlm)
# Description

A node.js http(s) client that allows to request unprotected and protected content using `Basic`, `NTLM v1` or `NTLM v2` authentication methods without using any dependency, uses native `http` and `https` nodejs modules.

`NTLM` authentication method will be used first if the server allows. If fails, `Basic` authentication will be used. This order cannot be changed but an authentication method (NTLM or Basic) can be used by default if needed.

> module with no DEPENDENCIES (low vulnerabilities)

This module is compatible with `Javascript` and `Typescript` projects and can work with or without session/cookie manager.

> CommonJS and ES6 compatible


# Installation

To use it in your project you must execute:
```
npm install --save node-client-ntlm
```

# Usage

You must import the module with `import` or `require` key:
```javascript
// ES6 import format
import { NtlmClient } from 'node-client-ntlm';
// CJS require format
const NtlmClient = require('node-client-ntlm').NtlmClient;
```

Once imported a instance is needed:
```javascript
const client = new NtlmClient();
```

Use the instance to request protected content using user credentials:
```javascript
client.request({
    url: 'https://ntlm.protected.data/collection',
    method: 'PUT',
    debug: false,
    body: { foo: 'bar' },
    headers: {
      'content-type': 'application/json'
    }
  }, 'user', 'pass', 'workstation', 'domain')
  .then((response) => {
    console.log('Content body of the response', response.body);
    console.log('Headers of the response', response.headers);
    console.log('StatusCode of the response', response.status);
  })
  .catch((error) => {
    console.error(error)
  })
```
> NOTE: Returns Promises.
# Examples
Full documentation available at https://m0rtadelo.github.io/ntlm-client/
Some usages examples of this module:
## GET request with full authentication
```javascript
const response = await client.request('http://ntlm.protected.data/items?id=26',
  'user', 'pass', 'workstation', 'domain'
);
```
## POST request (no data) with debug logger enabled
```javascript
const response = await client.request(
  { url: 'https://ntlm.protected.data/items?id=26', method: 'POST', debug: true },
  'user', 'pass'
);
```

## POST request (form data)
```javascript
const response = await client.request(
  { 
    url: 'https://ntlm.protected.data/items?id=26',
    method: 'POST',
    body: 'foo=bar&var1=val1',
    headers: {
      'content-type': 'application/x-www-form-urlencoded'
    }
  },
  'user', 'pass'
);
```

## POST request (json data)
```javascript
const response = await client.request(
  { 
    url: 'https://ntlm.protected.data/items?id=26',
    method: 'POST',
    body: { foo: 'bar' },
    headers: {
      'content-type': 'application/json'
    }
  },
  'user', 'pass'
);
```
## No auth GET request (standard https request with no authorization)
```javascript
const response = await client.request('https://ntlm.protected.data/items?id=26');
```
## GET request with session manager
```javascript
const tough = require('tough-cookie');

const response = await client.request('http://ntlm.protected.data/items?id=26',
  'user', 'pass', 'workstation', 'domain', { tough }
);
```
>NOTE: this module works out of the box with tough-cookie (`npm i --save tough-cookie`)

## GET request with predefined data session
```javascript
const response = await client.request(
  {
    url: 'http://ntlm.protected.data/items?id=26',
    headers = { cookie: 'cookieVar=cookieVal' }
  },
  'user', 'pass', 'workstation', 'domain'
);
```

## GET request using Basic auth (ntlm bypass)
```javascript
const response = await client.request(
  {
    url: 'http://ntlm.protected.data/items?id=26',
    authMethod: ['ntlm']
  },
  'user', 'pass', 'workstation', 'domain'
);
```
> To force Basic auth `ntlm` string should be in the authMethod array