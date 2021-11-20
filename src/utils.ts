import { IOptionsHTTP, IOptionsHTTPS } from './fetch.interface';

/**
 * Logs a message in the console if option.debug is enabled
 * @param ctx the context
 * @param options the Options object options
 * @param msg message to log
 * @return void
 */
export function log(ctx: any, options: IOptionsHTTP|IOptionsHTTPS, msg:any) {
  if (options.debug) {
    console.log('ntlm-client@m0rtadelo [' + ctx?.name + '] ' + msg);
  }
}
