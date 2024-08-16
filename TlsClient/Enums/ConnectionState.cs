namespace Konamiman.TlsClient.Enums;

/// <summary>
/// Represents the TLS connection state.
/// </summary>
public enum ConnectionState
{
    /// <summary>
    /// Initial state, ClientHello hasn't been sent yet.
    /// </summary>
    Initial = 0,

    /// <summary>
    /// Handhsake stage, waiting for server's ServerHello, certificate, and Finished.
    /// </summary>
    Handshake,

    /// <summary>
    /// Handshake completed, application data can be sent and receieved.
    /// </summary>
    Established,

    /// <summary>
    /// Close method invoked, no more application data can be sent, but it can be received from the server.
    /// </summary>
    LocallyClosed,

    /// <summary>
    /// The server did an orderly connection close, it won't send any more application data, but we can still send data.
    /// </summary>
    RemotelyClosed,

    /// <summary>
    /// Locally and remotely closed, the connection is no longer usable.
    /// </summary>
    FullClosed
}
