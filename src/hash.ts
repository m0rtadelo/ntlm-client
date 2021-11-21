import crypto from 'crypto';

/**
 * Generates a LM response
 * @param challenge the challenge
 * @param lmhash the lm hash
 * @return the LM response
 */
export function createLMResponse(challenge:any, lmhash:any): Buffer {
  const buf = Buffer.alloc(24);
  const pwBuffer = Buffer.alloc(21, 0);

  lmhash.copy(pwBuffer);

  calculateDES(pwBuffer.slice(0, 7), challenge).copy(buf);
  calculateDES(pwBuffer.slice(7, 14), challenge).copy(buf, 8);
  calculateDES(pwBuffer.slice(14), challenge).copy(buf, 16);

  return buf;
}

/**
 * Generates a LM hash password response
 * @param password the Password to hash
 * @return the LM Hash password
 */
export function createLMHash(password:string): Buffer {
  const buf = Buffer.alloc(16);
  const pwBuffer = Buffer.alloc(14);
  const magicKey = Buffer.from('KGS!@#$%', 'ascii');

  if (password.length > 14) {
    buf.fill(0);
    return buf;
  }

  pwBuffer.fill(0);
  pwBuffer.write(password.toUpperCase(), 0, 'ascii');

  return Buffer.concat([
    calculateDES(pwBuffer.slice(0, 7), magicKey),
    calculateDES(pwBuffer.slice(7), magicKey),
  ]);
}

/**
 * Calculate the DES-ECB
 * @param key param
 * @param message param
 * @return the result
 */
function calculateDES(key:any, message:any): Buffer {
  const desKey = Buffer.alloc(8);

  desKey[0] = key[0] & 0xFE;
  desKey[1] = ((key[0] << 7) & 0xFF) | (key[1] >> 1);
  desKey[2] = ((key[1] << 6) & 0xFF) | (key[2] >> 2);
  desKey[3] = ((key[2] << 5) & 0xFF) | (key[3] >> 3);
  desKey[4] = ((key[3] << 4) & 0xFF) | (key[4] >> 4);
  desKey[5] = ((key[4] << 3) & 0xFF) | (key[5] >> 5);
  desKey[6] = ((key[5] << 2) & 0xFF) | (key[6] >> 6);
  desKey[7] = (key[6] << 1) & 0xFF;

  for (let i = 0; i < 8; i++) {
    let parity = 0;

    for (let j = 1; j < 8; j++) {
      parity += (desKey[i] >> j) % 2;
    }

    desKey[i] |= (parity % 2) === 0 ? 1 : 0;
  }

  const des = crypto.createCipheriv('DES-ECB', desKey, '');
  return des.update(message);
}

/**
 * Geberates a NTLM response
 * @param challenge param
 * @param ntlmhash param
 * @return the response
 */
export function createNTLMResponse(challenge:any, ntlmhash:any): Buffer {
  const buf = Buffer.alloc(24);
  const ntlmBuffer = Buffer.alloc(21, 0);

  ntlmhash.copy(ntlmBuffer);

  calculateDES(ntlmBuffer.slice(0, 7), challenge).copy(buf);
  calculateDES(ntlmBuffer.slice(7, 14), challenge).copy(buf, 8);
  calculateDES(ntlmBuffer.slice(14), challenge).copy(buf, 16);

  return buf;
}

/**
 * Generates de digest hash for password
 * @param password param
 * @return the response
 */
export function createNTLMHash(password:string): Buffer {
  const md4sum = crypto.createHash('md4');
  md4sum.update(Buffer.from(password, 'ucs2'));
  return md4sum.digest();
}

/**
 * Generates a NTLM v2 digest hash
 * @param ntlmhash param
 * @param username param
 * @param authTargetName param
 * @return the response
 */
export function createNTLMv2Hash(ntlmhash:any, username:string, authTargetName:string|undefined): Buffer {
  const hmac = crypto.createHmac('md5', ntlmhash);
  hmac.update(Buffer.from(username.toUpperCase() + authTargetName, 'ucs2'));
  return hmac.digest();
}

/**
 * Generates a LM v2 response
 * @param type2message param
 * @param username param
 * @param ntlmhash param
 * @param nonce param
 * @param targetName param
 * @return the response
 */
export function createLMv2Response(
    type2message:any, username:string, ntlmhash:any, nonce:string, targetName:string,
): Buffer {
  const buf = Buffer.alloc(24);
  const ntlm2hash = createNTLMv2Hash(ntlmhash, username, targetName);
  const hmac = crypto.createHmac('md5', ntlm2hash);

  // server challenge
  type2message.challenge.copy(buf, 8);

  // client nonce
  buf.write(nonce || createPseudoRandomValue(16), 16, 'hex');

  // create hash
  hmac.update(buf.slice(8));
  const hashedBuffer = hmac.digest();

  hashedBuffer.copy(buf);

  return buf;
}

/**
 * Generates a NTLM v2 response
 * @param type2message param
 * @param username param
 * @param ntlmhash param
 * @param nonce param
 * @param targetName param
 * @return the response
 */
export function createNTLMv2Response(
    type2message: any,
    username:string,
    ntlmhash:any,
    nonce:string,
    targetName:string): Buffer {
  const buf = Buffer.alloc(48 + type2message.targetInfo.buffer.length);
  const ntlm2hash = createNTLMv2Hash(ntlmhash, username, targetName);
  const hmac = crypto.createHmac('md5', ntlm2hash);

  // the first 8 bytes are spare to store the hashed value before the blob

  // server challenge
  type2message.challenge.copy(buf, 8);

  // blob signature
  buf.writeUInt32BE(0x01010000, 16);

  // reserved
  buf.writeUInt32LE(0, 20);

  // timestamp
  // 11644473600000 = diff between 1970 and 1601
  const timestamp = ((Date.now() + 11644473600000) * 10000).toString(16);
  const timestampLow = Number('0x' + timestamp.substring(Math.max(0, timestamp.length - 8)));
  const timestampHigh = Number('0x' + timestamp.substring(0, Math.max(0, timestamp.length - 8)));

  buf.writeUInt32LE(timestampLow, 24);
  buf.writeUInt32LE(timestampHigh, 28);

  // random client nonce
  buf.write(nonce || createPseudoRandomValue(16), 32, 'hex');

  // zero
  buf.writeUInt32LE(0, 40);

  // complete target information block from type 2 message
  type2message.targetInfo.buffer.copy(buf, 44);

  // zero
  buf.writeUInt32LE(0, 44 + type2message.targetInfo.buffer.length);

  hmac.update(buf.slice(8));
  const hashedBuffer = hmac.digest();

  hashedBuffer.copy(buf);

  return buf;
}

/**
 * Generrates a random string with requested length
 * @param {number} length the length of the requested random string
 * @return {string} the random string
 */
export function createPseudoRandomValue(length:number): string {
  let str = '';
  while (str.length < length) {
    str += Math.floor(Math.random() * 16).toString(16);
  }
  return str;
}
