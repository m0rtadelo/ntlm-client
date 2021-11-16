import { Fetch } from './fetch';
import { IOptionsHTTP, IOptionsHTTPS, IResult } from './fetch.interface';
import { log } from './utils';
/**
 * NTLM Client to request protected content over http(s)
 */
export class NtlmClient {
  static tough: any;
  static cookie: any;
  static cookieJar: any;
  /**
   * Request a url (with Basic or NTLM authentication if required)
   * @param url the http(s) url to request from
   * @param [user] param
   * @param [pwd] param
   * @param [workstation] param
   * @param [domain] param
   * @param [options] object
   * @return response
   */
  public async request(
      url:string|IOptionsHTTP|IOptionsHTTPS, user:string='', pwd:string='', workstation?:string,
      domain?:string, options?: IOptionsHTTP|IOptionsHTTPS,
  ): Promise<IResult> {
    log({ name: 'request' }, options || { debug: (url as any).debug }, 'init request');
    return await Fetch.request(setOptions(url, user, pwd, workstation, domain, options));
  }
}
/**
   * Sets the options
   * @param url param
   * @param user param
   * @param pwd param
   * @param [workstation] param
   * @param [domain] param
   * @param [options] param
   * @return the response
   */
function setOptions(
    url:string|IOptionsHTTP|IOptionsHTTPS, user:string, pwd:string,
    workstation?:string, domain?:string, options?: IOptionsHTTP|IOptionsHTTPS,
): IOptionsHTTP|IOptionsHTTPS {
  options = options || {};
  if (typeof url === 'string') {
    options.url = url;
  } else {
    options = url;
  }
  options.user = user;
  options.pwd = pwd;
  options.workstation = workstation;
  options.domain = domain;
  options.method = options.method || 'GET';
  options.headers = options.headers || {};
  delete options.headers['Authorization'];
  NtlmClient.tough = options.tough || NtlmClient.tough;
  if (options.tough) {
    log({ name: 'setOptions' }, options, 'tough-cookie detected, using this cookie jar...');
    NtlmClient.cookie = NtlmClient.tough.Cookie;
    NtlmClient.cookieJar = new NtlmClient.tough.CookieJar();
  }
  options.cookie = NtlmClient.cookie;
  options.cookieJar = NtlmClient.cookieJar;
  log({ name: 'setOptions' }, options, 'options setted!');
  return options;
}
