import { IResult } from '../src/fetch.interface';
import { NtlmClient } from '../src/index';

let index = 0;
let client: NtlmClient;

const test1 = [{
  status: 200,
  body: '',
  headers: {},
  options: {},
}];

const test2 = [
  { status: 301, body: '', headers: { Location: 'http://redirect' }, options: {} },
  { status: 200, body: '', headers: {}, options: {} },
];

const test3 = [
  { status: 301, body: '', headers: { Location: 'http://redirect' }, options: {} },
];

const test4 = [
  { status: 401, body: '', headers: { 'www-authenticate': 'basic' }, options: {} },
  { status: 200, body: '', headers: {}, options: {} },
];

const test5 = [
  { status: 307, body: '', headers: { Location: 'http://redirect' }, options: {} },
  { status: 200, body: '', headers: {}, options: {} },
];

let mock:IResult[] = test1;

jest.mock('http', () => {
  return {
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
    mock = test1;
    const response:IResult = await client.request('http://mock');
    expect(response.status).toBe(200);
    expect(response.options.requests).toBe(1);
  });

  it('should intercept absolute Location with statusCode 301 request', async () => {
    mock = test2;
    const response:IResult = await client.request({ url: 'http://mock', debug: false, method: 'POST' });
    expect(response.status).toBe(200);
    expect(response.options.requests).toBe(2);
    expect(response.options.url).toBe(test2[0].headers.Location);
    expect(response.options.method).toBe('GET');
  });

  it('should intercept absolute Location with statusCode 307 request (no method change)', async () => {
    mock = test5;
    const response:IResult = await client.request({ url: 'http://mock', debug: false, method: 'POST' });
    expect(response.status).toBe(200);
    expect(response.options.requests).toBe(2);
    expect(response.options.url).toBe(test2[0].headers.Location);
    expect(response.options.method).toBe('POST');
  });

  it('should avoid infinite bucle', async () => {
    mock = test3;
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
    mock = test4;
    const response:IResult = await client.request('http://mock', 'user', 'pwd');
    expect(response.status).toBe(200);
    expect(response.options?.authMethod?.length).toBe(1);
    expect(response.options?.authMethod?.[0]).toBe('basic');
    expect(response.options?.requests).toBe(2);
    expect(response.options?.headers?.Authorization).toBe('Basic dXNlcjpwd2Q=');
  });
});
