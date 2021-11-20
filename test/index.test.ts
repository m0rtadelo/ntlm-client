/* eslint-disable require-jsdoc */
import { IResult } from '../src/fetch.interface';
import { NtlmClient } from '../src/index';

let index = 0;
let client: NtlmClient;

const Location = 'http://redirect';
const Location2 = '/redirect';
const Location3 = 'redirect.html';

let mock:IResult[];

jest.mock('http', () => {
  return {
    Agent: class {
      constructor(options:any) {};
      destroy() {};
    },
    request: (url: string, options: any, cb: any) => {
      const response = {
        on: (opt: any, fn: any) => {
          if (opt === 'data') {
            if (mock[index + 1]) {
              index++;
            }
            fn?.('data');
          } else {
            setTimeout(() => {
              fn?.('end');
            }, 100);
          }
        },
        statusCode: mock[index].status,
        body: mock[index].body,
        headers: mock[index].headers,
        resume: () => undefined,
      };
      cb(response);
      return {
        on: (opt: any, fn: any) => undefined,
        end: () => undefined,
      };
    },
  };
});

describe('index tests', () => {
  beforeEach(() => {
    index = 0;
    client = new NtlmClient();
  });

  it('should return status 200 for correct request without interception', async () => {
    mock = [{ status: 200, body: '', headers: {}, options: {} }];
    const response:IResult = await client.request('http://mock');
    expect(response.status).toBe(200);
    expect(response.options.requests).toBe(1);
  });

  it('should intercept absolute Location with statusCode 301 request', async () => {
    mock = [
      { status: 301, body: '', headers: { Location }, options: {} },
      { status: 200, body: '', headers: {}, options: {} },
    ];
    const response:IResult = await client.request({ url: 'http://mock', debug: false, method: 'POST' });
    expect(response.status).toBe(200);
    expect(response.options.requests).toBe(2);
    expect(response.options.url).toBe(Location);
    expect(response.options.method).toBe('GET');
  });

  it('should intercept relative Location with statusCode 301 request', async () => {
    mock = [
      { status: 301, body: '', headers: { Location: Location2 }, options: {} },
      { status: 200, body: '', headers: {}, options: {} },
    ];
    const response:IResult = await client.request({ url: 'http://mock/original/f.html', debug: false, method: 'POST' });
    expect(response.status).toBe(200);
    expect(response.options.requests).toBe(2);
    expect(response.options.url).toBe('http://mock'.concat(Location2));
    expect(response.options.method).toBe('GET');
  });

  it('should intercept relative Location (2) with statusCode 301 request', async () => {
    mock = [
      { status: 301, body: '', headers: { Location: Location3 }, options: {} },
      { status: 200, body: '', headers: {}, options: {} },
    ];
    const response:IResult = await client.request({ url: 'http://mock/original/f.html', debug: true, method: 'POST' });
    expect(response.status).toBe(200);
    expect(response.options.requests).toBe(2);
    expect(response.options.url).toBe('http://mock/original/'.concat(Location3));
    expect(response.options.method).toBe('GET');
  });

  it('should intercept absolute Location with statusCode 307 request (no method change)', async () => {
    mock = [
      { status: 307, body: '', headers: { Location }, options: {} },
      { status: 200, body: '', headers: {}, options: {} },
    ];
    const response:IResult = await client.request({ url: 'http://mock', debug: false, method: 'POST' });
    expect(response.status).toBe(200);
    expect(response.options.requests).toBe(2);
    expect(response.options.url).toBe(Location);
    expect(response.options.method).toBe('POST');
  });

  it('should avoid infinite bucle', async () => {
    mock = [
      { status: 301, body: '', headers: { Location }, options: {} },
    ];
    let err;
    try {
      const response: IResult = await client.request('http://mock');
      console.log(response);
    } catch (error) {
      err = error;
    }
    expect(err).toBeDefined();
  });

  it('should use basic auth if server allows', async () => {
    mock = [
      { status: 401, body: '', headers: { 'www-authenticate': 'basic' }, options: {} },
      { status: 200, body: '', headers: {}, options: {} },
    ];
    const response:IResult = await client.request('http://mock', 'user', 'pwd');
    expect(response.status).toBe(200);
    expect(response.options?.authMethod?.length).toBe(1);
    expect(response.options?.authMethod?.[0]).toBe('basic');
    expect(response.options?.requests).toBe(2);
    expect(response.options?.headers?.Authorization).toBe('Basic dXNlcjpwd2Q=');
  });

  it('should use ntlm auth as first option if server allows', async () =>{
    mock = [
      { status: 401, body: '', headers: { 'www-authenticate': 'basic,negotiate,ntlm' }, options: {} },
      { status: 200, body: '', headers: {}, options: {} },
    ];
    const response:IResult = await client.request('http://mock', 'user', 'pwd');
    expect(response.status).toBe(200);
  });
});
