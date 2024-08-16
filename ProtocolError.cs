using Konamiman.TlsClient.Enums;
using System;

namespace Konamiman.TlsClient;

/// <summary>
/// Exception that is thrown whenever a violation of the TLS protocol is detected.
/// The exception is captured, an alert record is sent, and then the connection is closed.
/// </summary>
internal class ProtocolError : Exception
{
    /// <summary>
    /// Alert code to be sent to the server.
    /// </summary>
    public AlertCode AlertCode { get; }

    /// <summary>
    /// Creates a new instance of the class.
    /// </summary>
    /// <param name="alertCode">Alert code to be sent to the server.</param>
    /// <param name="errorMessage">Associated informative error message to record.</param>
    public ProtocolError(AlertCode alertCode, string errorMessage) : base(errorMessage)
    {
        this.AlertCode = alertCode;
    }
}
