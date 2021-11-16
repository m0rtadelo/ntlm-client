import http from 'http';
import https from 'https';
import { IOptionsHTTP, IOptionsHTTPS, IResult } from './fetch.interface';
import { createBasicMessage, createType1Message, createType3Message, decodeType2Message } from './ntlm';
import { log } from './utils';

/**
 * Fetch client to request protected content over http(s)
 */
export class Fetch {
  /**
   * Requests a NTLM protected http(s) url using options values
   * @param options param
   * @return the response
   */
  static request(options:IOptionsHTTP|IOptionsHTTPS): Promise<IResult> {
    log(this, options, 'request init for url: ' + options?.url);
    const getProtocol = (url:string|undefined) => url?.startsWith('https://') ? https : http;
    const protocol = getProtocol(options.url);
    return new Promise((res, rej) => {
      Fetch.get(options, protocol, res, rej);
    });
  }

  /**
   * Requests a NTLM protected http(s) url using param values
   * @param options param
   * @param protocol param
   * @param res param
   * @param rej param
   * @return void
   */
  private static get(options: IOptionsHTTP|IOptionsHTTPS, protocol: typeof http| typeof https, res: any, rej: any) {
    const result: IResult = { body: '', headers: {}, status: 0, options };
    try {
      log(this, options, 'requesting ' + options.url);
      options.headers = options.headers || {};
      if (options.cookieJar) {
        options.headers.cookie =
          options.cookieJar.getCookiesSync(options.url).map((c:any) => c.cookieString()).join('; ');
      }
      log(this, options, 'headers = ' + JSON.stringify(options.headers));
      const req = protocol.request((options.url as string), options, (response) => {
        options.headers = options.headers || {};
        response.on('data', (data) => {
          log(this, options, 'data received ' + data.length + ' bytes chunk');
          result.body += data;
        });
        response.on('end', () => {
          if (result.resolve) {
            log(this, options, 'resolve with ' + result.status);
            delete result.resolve;
            res(result);
          }
        });
        log(this, options, 'response ' + response?.statusCode + ' from ' + options.url);
        if (options.cookieJar && options.cookie) {
          const cookiesHeader = response.headers['set-cookie'] || [];
          cookiesHeader.forEach((cookie:any) => {
            log(this, options, 'setting cookie');
            options.cookieJar.setCookieSync(options.cookie.parse(cookie), options.url);
          });
        }
        result.resolve = false;
        result.status = response.statusCode || 0;
        result.headers = response.headers;
        const authMethods = response.headers?.['www-authenticate']?.split(',').map((i) => i.trim().toLowerCase());
        if (result.status === 401 && options.user && options.pwd && authMethods?.indexOf('ntlm') !== -1) {
          log(this, options, 'NTLM Step 1 (ntlm authenticate method allowed)');
          options.agent = options.agent || new protocol.Agent({ keepAlive: true, maxSockets: 1 });
          options.headers['Authorization'] = createType1Message(options.workstation, options.domain);
          log(this, options, 'Authorization header = '+ options.headers['Authorization']);
          Fetch.get(options, protocol, res, rej);
        } else if (result.status === 401 && options.user && options.pwd && authMethods?.indexOf('basic') !== -1) {
          options.headers['Authorization'] = createBasicMessage(options.user, options.pwd);
          delete options.user;
          delete options.pwd;
          Fetch.get(options, protocol, res, rej);
        } else if (
          result.status > 399 && result.status < 500 &&
          options.user && options.pwd &&
          options.headers?.['Authorization']
        ) {
          const t2m = decodeType2Message(result.headers['www-authenticate']);
          log(this, options, 'NTLM Step 2 = ' + JSON.stringify(t2m));
          const authHeader = createType3Message(t2m, options.user, options.pwd, options.workstation, options.domain);
          options.headers['Authorization'] = authHeader;
          delete options.user;
          delete options.pwd;
          response.resume();
          Fetch.get(options, protocol, res, rej);
        } else {
          (options.agent as https.Agent|https.Agent)?.destroy();
          log(this, options, 'this request can be resolved');
          result.resolve = true;
        }
      });
      req.on('error', (err) => {
        log(this, options, 'error on request!');
        rej(err);
      });
      if (options.body) {
        req.write(options.body);
      }
      req.end();
    } catch (error) {
      log(this, options, 'error on try!');
      rej(error);
    }
  }
}
