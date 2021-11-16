export const NTLMFLAG_NEGOTIATE_UNICODE = 1<<0;
/* Indicates that Unicode strings are supported for use in security buffer
   data. */

export const NTLMFLAG_NEGOTIATE_OEM = 1<<1;
/* Indicates that OEM strings are supported for use in security buffer data. */

export const NTLMFLAG_REQUEST_TARGET = 1<<2;
/* Requests that the server's authentication realm be included in the Type 2
   message. */

/* unknown (1<<3) */
export const NTLMFLAG_NEGOTIATE_SIGN = 1<<4;
/* Specifies that authenticated communication between the client and server
   should carry a digital signature (message integrity). */

export const NTLMFLAG_NEGOTIATE_SEAL = 1<<5;
/* Specifies that authenticated communication between the client and server
   should be encrypted (message confidentiality). */

export const NTLMFLAG_NEGOTIATE_DATAGRAM_STYLE = 1<<6;
/* Indicates that datagram authentication is being used. */

export const NTLMFLAG_NEGOTIATE_LM_KEY = 1<<7;
/* Indicates that the LAN Manager session key should be used for signing and
   sealing authenticated communications. */

export const NTLMFLAG_NEGOTIATE_NETWARE = 1<<8;
/* unknown purpose */

export const NTLMFLAG_NEGOTIATE_NTLM_KEY = 1<<9;
/* Indicates that NTLM authentication is being used. */

/* unknown (1<<10) */

export const NTLMFLAG_NEGOTIATE_ANONYMOUS = 1<<11;
/* Sent by the client in the Type 3 message to indicate that an anonymous
   context has been established. This also affects the response fields. */

export const NTLMFLAG_NEGOTIATE_DOMAIN_SUPPLIED = 1<<12;
/* Sent by the client in the Type 1 message to indicate that a desired
   authentication realm is included in the message. */

export const NTLMFLAG_NEGOTIATE_WORKSTATION_SUPPLIED = 1<<13;
/* Sent by the client in the Type 1 message to indicate that the client
   workstation's name is included in the message. */

export const NTLMFLAG_NEGOTIATE_LOCAL_CALL = 1<<14;
/* Sent by the server to indicate that the server and client are on the same
   machine. Implies that the client may use a pre-established local security
   context rather than responding to the challenge. */

export const NTLMFLAG_NEGOTIATE_ALWAYS_SIGN = 1<<15;
/* Indicates that authenticated communication between the client and server
   should be signed with a "dummy" signature. */

export const NTLMFLAG_TARGET_TYPE_DOMAIN = 1<<16;
/* Sent by the server in the Type 2 message to indicate that the target
   authentication realm is a domain. */

export const NTLMFLAG_TARGET_TYPE_SERVER = 1<<17;
/* Sent by the server in the Type 2 message to indicate that the target
   authentication realm is a server. */

export const NTLMFLAG_TARGET_TYPE_SHARE = 1<<18;
/* Sent by the server in the Type 2 message to indicate that the target
   authentication realm is a share. Presumably, this is for share-level
   authentication. Usage is unclear. */

export const NTLMFLAG_NEGOTIATE_NTLM2_KEY = 1<<19;
/* Indicates that the NTLM2 signing and sealing scheme should be used for
   protecting authenticated communications. */

export const NTLMFLAG_REQUEST_INIT_RESPONSE = 1<<20;
/* unknown purpose */

export const NTLMFLAG_REQUEST_ACCEPT_RESPONSE = 1<<21;
/* unknown purpose */

export const NTLMFLAG_REQUEST_NONNT_SESSION_KEY = 1<<22;
/* unknown purpose */

export const NTLMFLAG_NEGOTIATE_TARGET_INFO = 1<<23;
/* Sent by the server in the Type 2 message to indicate that it is including a
   Target Information block in the message. */

/* unknown (1<24) */
/* unknown (1<25) */
/* unknown (1<26) */
/* unknown (1<27) */
/* unknown (1<28) */

export const NTLMFLAG_NEGOTIATE_128 = 1<<29;
/* Indicates that 128-bit encryption is supported. */

export const NTLMFLAG_NEGOTIATE_KEY_EXCHANGE = 1<<30;
/* Indicates that the client will provide an encrypted master key in
   the "Session Key" field of the Type 3 message. */

export const NTLMFLAG_NEGOTIATE_56 = 1<<31;
/* Indicates that 56-bit encryption is supported. */
