import { NtlmClient } from '../src';
import { IResult } from '../src/fetch.interface';
const express = require('express');
const bodyParser = require('body-parser');
const ntlm = require('express-ntlm');

const app = express();
let client: NtlmClient;

app.use(bodyParser.json());

const authenticateUser = (req: any, res: any, next: any) => {
  if (req.ntlm && req.ntlm.UserName && req.ntlm.UserName === 'user') {
    req.user = { username: req.ntlm.UserName };
    next();
  } else {
    res.status(401).json({ message: 'NTLM authentication failed' });
  }
};

app.use(ntlm());

app.get('/', authenticateUser, (req: any, res: any) => {
  res.send(`Authenticated Successfully! Welcome ${req.user.username}`);
});

const PORT = process.env.PORT || 3081;
const server = app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

describe('mock test', () => {
  beforeEach(() => {
    client = new NtlmClient();
  });
  afterAll(() => {
    server.close(() => {
    });
  });
  it('should work with real server (correct username)', async () => {
    const response:IResult = await client.request(`http://localhost:${PORT}`, 'user', 'pwd');
    expect(response.status).toBe(200);
  });
  it('should work with real server (incorrect username)', async () => {
    const response:IResult = await client.request(`http://localhost:${PORT}`, 'baduser', 'pwd');
    expect(response.status).toBe(401);
  });
});
