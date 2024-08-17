# TLS 1.3 client

This is a [RFC8446](https://datatracker.ietf.org/doc/html/rfc8446) compliant TLS 1.3 client implementation written in C# and targetting [.NET 8](https://dotnet.microsoft.com/en-us/download/dotnet/8.0). As simple as that.


## Why?

Just for fun/educational purposes. I wanted to make sure that I understood the TLS specification to the point of being able to write a full implementation "from scratch"<sup>1</sup>, so I just did it.

This implementation works but it hasn't been extensively tested, and there's probably plenty of room for improvement in the performance side (e.g. I use [LINQ](https://learn.microsoft.com/en-us/dotnet/csharp/linq/) extensively because it makes the code for handling collections of bytes really easy to write and read, but that's probably not the wiser choice from a performance perspective). Therefore I **don't** recommend using it in production scenarios, at least not before you thoroughly test it to make sure that it's appropriate given your performance, stability and security requirements (also doesn't .NET implement TLS natively anyway?)

<sup>1</sup>I'm actually using the .NET built-in functionality for the purely cryptographic parts (HMAC, SHA256/384, AES, certificate verification).


## How to use

1. Create an instance of a class implementing `IDataTransport`, most likely you want an instance of `TcpDataTransport`.
2. Create an instance of `TlsClientConnection`, passing the data transport class and optionally a private key (a random one will be created otherwise) and a host name (to be sent in [the Server Name Indication extension](https://datatracker.ietf.org/doc/html/rfc6066#section-3)).
3. By default the connection will be aborted if the verification of the server certificate fails, if you don't want this to happen set the `AbortIfInvalidCertificate` property to false.
4. Check the `State` property until it reaches the value `Established`.
5. Use the `GetApplicationData` and `SendApplicationData` methods as appropriate.
6. When you are done just execute the `Close` method. You should also periodically check `State` to detect if the server has closed the connection (the client class may also close the connection by itself if it detects some error condition).

There are other public properties that can be useful for debugging purposes (e.g. `Certificates`, `AlertSent`, `AlertReceived`) and a collection of events for significant occurrences (e.g. `StateChanged`), see [the source of `TlsClientConnection`](https://github.com/Konamiman/TlsClient/blob/master/TlsClient/TlsClientConnection.cs) for the details.

See [the `TlsConsole` project](https://github.com/Konamiman/TlsClient/blob/master/TlsConsole/Program.cs) for a very simple yet functional example. It's a minimal Telnet-like application that once the connection is established will simply send whatever you type and print out whatever is received. A typical minimal test you can perform using it is connecting to a web server and sending `GET / HTTP/1.1` followed by `Host: hostname.com` and an empty line.


## The state machine

One thing worth knowing about how `TlsClientConnection` works under the hood is that there's a simple state machine that handles the handshake process, receiving and processing the server handshake messages, sending whatever client handshake messages are needed and upating the internal state of the class. Post-handshake, the state machine checks if the connection is still open and if further handshake messages (e.g. for key update) are received.

This state machine runs whenever the `State`, `CanSend` or `CanReceive` properties are read, and when `GetApplicationData` and `SendApplicationData` are invoked. Thus by periodically checking the value of `State` and by sending/receiving data you are all set to keep the state machine running.


## What's implemented
- TLS 1.3 client protocol as per [RFC8446](https://datatracker.ietf.org/doc/html/rfc8446) (obviously).
- X25519 for key exchange (code "acquired" from [a gist by Hans Wolff](https://gist.github.com/hanswolff/7625227)).
- The `TLS_AES_128_GCM_SHA256` and `TLS_AES_256_GCM_SHA384` cipher suites.
- The `ecdsa_secp256r1_sha256`, `rsa_pss_rsae_sha256` and `rsa_pkcs1_sha256` algorithgms, together with their SHA384 versions, for signature verification.
- The [Server Name Indication extension](https://datatracker.ietf.org/doc/html/rfc6066#section-3).
- [Maximum Fragment Length negotiation](https://datatracker.ietf.org/doc/html/rfc6066#section-4) (fixed to a fragment length value of 512 bytes).
- Automatic client key update every 20M records sent (see the `MAX_RECORDS_PER_KEY` constant).

## What's NOT implemented

- Client certificates.
- "Advanced" server certificate validation beyond the signature verification (e.g. expiration date).
- The `HelloRetryRequest` message (if one is received the connection is aborted). Note: the first `ClientHello` message sent is already the best one we can craft, so if it isn't good for the server, there's nothing else we can do.
- Pre-shared keys.
- Session resumption (`NewSessionTicket` messages are ignored).
- A few other bits that aren't strictly necessary for interoperability with servers, search for `TODO:` comments for the details.

