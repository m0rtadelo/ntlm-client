import { NTLMFLAG_NEGOTIATE_OEM, NTLMFLAG_REQUEST_TARGET, NTLMFLAG_NEGOTIATE_NTLM_KEY,
  NTLMFLAG_NEGOTIATE_NTLM2_KEY, NTLMFLAG_NEGOTIATE_ALWAYS_SIGN, NTLMFLAG_NEGOTIATE_TARGET_INFO } from './flags';
import os from 'os';
import { createNTLMHash, createPseudoRandomValue, createLMv2Response, createNTLMv2Response,
  createLMHash, createLMResponse, createNTLMResponse } from './hash';
import { IType2 } from './fetch.interface';

const NTLMSIGNATURE = 'NTLMSSP\0';
/**
 * Returns the basic auth header
 * @param user the username
 * @param pwd the password
 * @return the basic auth header
 */
export function createBasicMessage(user:string, pwd:string): string {
  return 'Basic ' + Buffer.from(user + ':' + pwd, 'utf8').toString('base64');
}
/**
 * Returns the type1 NTLM token
 * @param workstation param
 * @param target param
 * @return the NTLM type1 token
 */
export function createType1Message(workstation:string|undefined=undefined, target:string|undefined=undefined): string {
  let dataPos = 32;
  let pos = 0;
  const buf = Buffer.alloc(1024);

  workstation = workstation === undefined ? os.hostname() : workstation;
  target = target === undefined ? '' : target;

  // signature
  buf.write(NTLMSIGNATURE, pos, NTLMSIGNATURE.length, 'ascii');
  pos += NTLMSIGNATURE.length;

  // message type
  buf.writeUInt32LE(1, pos);
  pos += 4;

  // flags
  buf.writeUInt32LE(NTLMFLAG_NEGOTIATE_OEM |
            NTLMFLAG_REQUEST_TARGET |
            NTLMFLAG_NEGOTIATE_NTLM_KEY |
            NTLMFLAG_NEGOTIATE_NTLM2_KEY |
            NTLMFLAG_NEGOTIATE_ALWAYS_SIGN, pos);
  pos += 4;

  // domain security buffer
  buf.writeUInt16LE(target.length, pos);
  pos += 2;
  buf.writeUInt16LE(target.length, pos);
  pos += 2;
  buf.writeUInt32LE(target.length === 0 ? 0 : dataPos, pos);
  pos += 4;

  if (target.length > 0) {
    dataPos += buf.write(target, dataPos, 'ascii');
  }

  // workstation security buffer
  buf.writeUInt16LE(workstation.length, pos);
  pos += 2;
  buf.writeUInt16LE(workstation.length, pos);
  pos += 2;
  buf.writeUInt32LE(workstation.length === 0 ? 0 : dataPos, pos);

  if (workstation.length > 0) {
    dataPos += buf.write(workstation, dataPos, 'ascii');
  }

  return 'NTLM ' + buf.toString('base64', 0, dataPos);
}

/**
 * Returns decoded type2 message
 * @param str param
 * @return decoded object
 */
export function decodeType2Message(str:any): IType2 {
  if (str === undefined) {
    throw new Error('Invalid argument');
  }

  // convenience
  if (Object.prototype.toString.call(str) !== '[object String]') {
    if (str.hasOwnProperty('headers') && str.headers.hasOwnProperty('www-authenticate')) {
      str = str.headers['www-authenticate'];
    } else {
      throw new Error('Invalid argument');
    }
  }

  const ntlmMatch = /^NTLM ([^,\s]+)/.exec(str);

  if (ntlmMatch) {
    str = ntlmMatch[1];
  }

  const buf = Buffer.from(str, 'base64');
  const obj: IType2 = {};

  // check signature
  if (buf.toString('ascii', 0, NTLMSIGNATURE.length) !== NTLMSIGNATURE) {
    throw new Error('Invalid message signature: ' + str);
  }

  // check message type
  if (buf.readUInt32LE(NTLMSIGNATURE.length) !== 2) {
    throw new Error('Invalid message type (no type 2)');
  }

  // read flags
  obj.flags = buf.readUInt32LE(20);

  obj.encoding = (obj.flags & NTLMFLAG_NEGOTIATE_OEM) ? 'ascii' : 'ucs2';

  obj.version = (obj.flags & NTLMFLAG_NEGOTIATE_NTLM2_KEY) ? 2 : 1;

  obj.challenge = buf.slice(24, 32);

  // read target name
  obj.targetName = (function() {
    const length = buf.readUInt16LE(12);
    // skipping allocated space
    const offset = buf.readUInt32LE(16);

    if (length === 0) {
      return '';
    }

    if ((offset + length) > buf.length || offset < 32) {
      throw new Error('Bad type 2 message');
    }

    return buf.toString(obj.encoding, offset, offset + length);
  })();

  // read target info
  if (obj.flags & NTLMFLAG_NEGOTIATE_TARGET_INFO) {
    obj.targetInfo = (function() {
      const info:any = {};

      const length = buf.readUInt16LE(40);
      // skipping allocated space
      const offset = buf.readUInt32LE(44);

      const targetInfoBuffer = Buffer.alloc(length);
      buf.copy(targetInfoBuffer, 0, offset, offset + length);

      if (length === 0) {
        return info;
      }

      if ((offset + length) > buf.length || offset < 32) {
        throw new Error('Bad type 2 message');
      }

      let pos = offset;

      while (pos < (offset + length)) {
        const blockType = buf.readUInt16LE(pos);
        pos += 2;
        const blockLength = buf.readUInt16LE(pos);
        pos += 2;

        if (blockType === 0) {
          // reached the terminator subblock
          break;
        }

        let blockTypeStr;

        switch (blockType) {
          case 1:
            blockTypeStr = 'SERVER';
            break;
          case 2:
            blockTypeStr = 'DOMAIN';
            break;
          case 3:
            blockTypeStr = 'FQDN';
            break;
          case 4:
            blockTypeStr = 'DNS';
            break;
          case 5:
            blockTypeStr = 'PARENT_DNS';
            break;
          default:
            blockTypeStr = '';
            break;
        }

        if (blockTypeStr) {
          info[blockTypeStr] = buf.toString('ucs2', pos, pos + blockLength);
        }

        pos += blockLength;
      }

      return {
        parsed: info,
        buffer: targetInfoBuffer,
      };
    })();
  }

  return obj;
}

/**
 * Returns type3 NTLM token
 * @param type2Message param
 * @param username param
 * @param password param
 * @param [workstation] param
 * @param [target] param
 * @return NTLM type3 token
 */
export function createType3Message(
    type2Message:IType2, username:string, password:string, workstation?:string, target?:string,
): string {
  let dataPos = 52;
  const buf = Buffer.alloc(1024);

  if (workstation === undefined) {
    workstation = os.hostname();
  }

  if (target === undefined) {
    target = type2Message.targetName || '';
  }

  // signature
  buf.write(NTLMSIGNATURE, 0, NTLMSIGNATURE.length, 'ascii');

  // message type
  buf.writeUInt32LE(3, 8);

  if (type2Message.version === 2) {
    dataPos = 64;

    const ntlmHash = createNTLMHash(password);
    const nonce = createPseudoRandomValue(16);
    const lmv2 = createLMv2Response(type2Message, username, ntlmHash, nonce, target);
    const ntlmv2 = createNTLMv2Response(type2Message, username, ntlmHash, nonce, target);

    // lmv2 security buffer
    buf.writeUInt16LE(lmv2.length, 12);
    buf.writeUInt16LE(lmv2.length, 14);
    buf.writeUInt32LE(dataPos, 16);

    lmv2.copy(buf, dataPos);
    dataPos += lmv2.length;

    // ntlmv2 security buffer
    buf.writeUInt16LE(ntlmv2.length, 20);
    buf.writeUInt16LE(ntlmv2.length, 22);
    buf.writeUInt32LE(dataPos, 24);

    ntlmv2.copy(buf, dataPos);
    dataPos += ntlmv2.length;
  } else {
    const lmHash = createLMHash(password);
    const ntlmHash = createNTLMHash(password);
    const lm = createLMResponse(type2Message.challenge, lmHash);
    const ntlm = createNTLMResponse(type2Message.challenge, ntlmHash);

    // lm security buffer
    buf.writeUInt16LE(lm.length, 12);
    buf.writeUInt16LE(lm.length, 14);
    buf.writeUInt32LE(dataPos, 16);

    lm.copy(buf, dataPos);
    dataPos += lm.length;

    // ntlm security buffer
    buf.writeUInt16LE(ntlm.length, 20);
    buf.writeUInt16LE(ntlm.length, 22);
    buf.writeUInt32LE(dataPos, 24);

    ntlm.copy(buf, dataPos);
    dataPos += ntlm.length;
  }

  // target name security buffer
  buf.writeUInt16LE(type2Message.encoding === 'ascii' ? target.length : target.length * 2, 28);
  buf.writeUInt16LE(type2Message.encoding === 'ascii' ? target.length : target.length * 2, 30);
  buf.writeUInt32LE(dataPos, 32);

  dataPos += buf.write(target, dataPos, type2Message.encoding);

  // user name security buffer
  buf.writeUInt16LE(type2Message.encoding === 'ascii' ? username.length : username.length * 2, 36);
  buf.writeUInt16LE(type2Message.encoding === 'ascii' ? username.length : username.length * 2, 38);
  buf.writeUInt32LE(dataPos, 40);

  dataPos += buf.write(username, dataPos, type2Message.encoding);

  // workstation name security buffer
  buf.writeUInt16LE(type2Message.encoding === 'ascii' ? workstation.length : workstation.length * 2, 44);
  buf.writeUInt16LE(type2Message.encoding === 'ascii' ? workstation.length : workstation.length * 2, 46);
  buf.writeUInt32LE(dataPos, 48);

  dataPos += buf.write(workstation, dataPos, type2Message.encoding);

  if (type2Message.version === 2) {
    // session key security buffer
    buf.writeUInt16LE(0, 52);
    buf.writeUInt16LE(0, 54);
    buf.writeUInt32LE(0, 56);

    // flags
    buf.writeUInt32LE(type2Message.flags, 60);
  }

  return 'NTLM ' + buf.toString('base64', 0, dataPos);
}
