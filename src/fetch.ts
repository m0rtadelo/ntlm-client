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
      Fetch.setHeaders(options);
      const req = protocol.request((options.url as string), options, (response) => {
        log(this, options, 'response ' + response?.statusCode + ' from ' + options.url);
        Fetch.setListeners(response, options, result, res);
        Fetch.setCookie(options, response);
        const authMethods = Fetch.getAuthMethods(result, response);
        if (
          result.status === 401 &&
          options.user && options.pwd &&
          authMethods?.indexOf('ntlm') !== -1 &&
          !options.authMethod?.includes('ntlm')
        ) {
          Fetch.executeNTLM1(options, protocol, res, rej);
        } else if (
          result.status === 401 &&
          options.user && options.pwd &&
          authMethods?.indexOf('basic') !== -1 &&
          !options.authMethod?.includes('basic')
        ) {
          Fetch.executeBasic(options, protocol, res, rej);
        } else if (
          result.status > 399 && result.status < 500 &&
          options.user && options.pwd &&
          options.headers?.['Authorization'] &&
          options.authMethod?.includes('ntlm')
        ) {
          Fetch.executeNTLM2(result, options, response, protocol, res, rej);
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
  /**
   * Sets the Cookie header
   * @param options param
   * @return void
   */
  private static setHeaders(options: IOptionsHTTP | IOptionsHTTPS) {
    options.headers = options.headers || {};
    options.authMethod = options.authMethod || [];
    if (options.cookieJar) {
      options.headers.cookie =
        options.cookieJar.getCookiesSync(options.url).map((c: any) => c.cookieString()).join('; ');
    }
    log({ name: 'setHeaders' }, options, 'headers = ' + JSON.stringify(options.headers));
  }

  /**
   * Execute the NTLM step 2 request
   * @param result param
   * @param options param
   * @param response param
   * @param protocol param
   * @param res param
   * @param rej param
   * @return void
   */
  private static executeNTLM2(
      result: IResult, options: IOptionsHTTP | IOptionsHTTPS, response: http.IncomingMessage,
      protocol: typeof https | typeof http, res: any, rej: any,
  ) {
    options.headers = options.headers || {};
    const t2m = decodeType2Message(result.headers['www-authenticate']);
    log(this, options, 'NTLM Step 2 = ' + JSON.stringify(t2m));
    const authHeader = createType3Message(
        t2m, options?.user || '', options?.pwd || '', options?.workstation, options?.domain,
    );
    options.headers['Authorization'] = authHeader;
    Fetch.deleteCredentials(options);
    response.resume();
    Fetch.get(options, protocol, res, rej);
  }

  /**
   * Execute the Basic request
   * @param options param
   * @param protocol param
   * @param res param
   * @param rej param
   * @return void
   */
  private static executeBasic(
      options: IOptionsHTTP | IOptionsHTTPS, protocol: typeof https | typeof http, res: any, rej: any,
  ) {
    options.authMethod?.push('basic');
    options.headers = options.headers || {};
    options.headers['Authorization'] = createBasicMessage(options?.user || '', options?.pwd || '');
    Fetch.deleteCredentials(options);
    Fetch.get(options, protocol, res, rej);
  }
  /**
   * Deletes credentials from option object
   * @param options param
   * @return void
   */
  private static deleteCredentials(options: IOptionsHTTP | IOptionsHTTPS) {
    delete options.user;
    delete options.pwd;
    delete options.workstation;
    delete options.domain;
  }
  /**
   * xecute the NTLM step 1 request
   * @param options param
   * @param protocol param
   * @param res param
   * @param rej param
   * @return void
   */
  private static executeNTLM1(
      options: IOptionsHTTP | IOptionsHTTPS, protocol: typeof https | typeof http, res: any, rej: any,
  ) {
    options.headers = options.headers || {};
    options.authMethod?.push('ntlm');
    log(this, options, 'NTLM Step 1 (ntlm authenticate method allowed)');
    options.agent = options.agent || new protocol.Agent({ keepAlive: true, maxSockets: 1 });
    options.headers['Authorization'] = createType1Message(options.workstation, options.domain);
    log(this, options, 'Authorization header = ' + options.headers['Authorization']);
    Fetch.get(options, protocol, res, rej);
  }

  /**
   * Returns the available server auth methods
   * @param result param
   * @param response param
   * @returns authMethods
   */
  private static getAuthMethods(result: IResult, response: http.IncomingMessage): Array<string>|undefined {
    result.resolve = false;
    result.status = response.statusCode || 0;
    result.headers = response.headers;
    return response.headers?.['www-authenticate']?.split(',').map((i) => i.trim().toLowerCase());
  }

  /**
   * Adds the cookie (if one) from header into the jar
   * @param options param
   * @param response param
   * @return void
   */
  private static setCookie(options: IOptionsHTTP | IOptionsHTTPS, response: http.IncomingMessage) {
    if (options.cookieJar && options.cookie) {
      const cookiesHeader = response.headers['set-cookie'] || [];
      cookiesHeader.forEach((cookie: any) => {
        log(this, options, 'setting cookie');
        options.cookieJar.setCookieSync(options.cookie.parse(cookie), options.url);
      });
    }
  }

  /**
   * Sets the response listeners
   * @param response param
   * @param options param
   * @param result param
   * @param res param
   * @return void
   */
  private static setListeners(
      response: http.IncomingMessage, options: IOptionsHTTP | IOptionsHTTPS, result: IResult, res: any,
  ) {
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
  }
}
