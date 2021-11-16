import http from 'http';
import https from 'https';

/**
 * Contains the result of the main function call.
 */
export interface IResult {
  /** Data from the body response */
  body: any,
  /** Headers from the response */
  headers: any,
  /** StatusCode from the response */
  status: number,
  resolve?: boolean,
  /** Result options data */
  options: IOptionsHTTP|IOptionsHTTPS,
}

interface IOptionsCustom {
  /** content (body) of the request */
  body?: any,
  /** http(s) url of the protected resource */
  url?: string,
  /** username of valid user (can be DOMAIN\username format) */
  user?: string,
  /** password of the username */
  pwd?: string,
  /** workstation id (calculated if undefined) */
  workstation?:string,
  /** domain/target validation */
  domain?:string,
  /** Enable the logger for debug purposes */
  debug?:boolean,
  /** Sets the tough-cookie module to enable session */
  tough?: any,
  cookie?: any,
  cookieJar?: any,
}
export interface IOptionsHTTP extends http.RequestOptions, IOptionsCustom {
}
export interface IOptionsHTTPS extends https.RequestOptions, IOptionsCustom {
}

export interface IType2 {
  flags?: any,
  encoding?: BufferEncoding,
  version?: number,
  challenge?: Buffer,
  targetName?: string,
  targetInfo?: any
}
