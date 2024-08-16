using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Konamiman.TlsClient.DataTransport;

/// <summary>
/// IDataTransport wrapper around a TCP connection.
/// </summary>
public class TcpDataTransport : IDataTransport
{
    readonly TcpClient client;
    readonly string host;
    readonly int port;
    bool locallyClosed = false;

    public TcpDataTransport(string host, int port)
    {
        client = new TcpClient(AddressFamily.InterNetwork);
        this.host = host;
        this.port = port;
    }

    public void Connect()
    {
        client.Connect(host, port);
    }

    public void Close()
    {
        client.Close();
        locallyClosed = true;
    }

    public bool HasDataToReceive()
    {
        return client.Available > 0;
    }

    public bool IsLocallyClosed()
    {
        return locallyClosed;
    }

    public bool IsRemotelyClosed()
    {
        var state = GetConnectionState();
        return state is TcpState.Closed or TcpState.CloseWait or null;
    }

    public int Receive(byte[] destination, int index, int length)
    {
        try
        {
            return HasDataToReceive() ? client.GetStream().Read(destination, index, length) : 0;
        }
        catch
        {
            return 0;
        }
    }

    public bool Send(byte[] data, int index = 0, int? length = null)
    {
        length ??= data.Length - index;

        if (IsRemotelyClosed())
        {
            return false;
        }

        try
        {
            client.GetStream().Write(data, index, length.Value);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public TcpState? GetConnectionState()
    {
        var info = IPGlobalProperties.GetIPGlobalProperties()
          .GetActiveTcpConnections()
          .SingleOrDefault(x => x.LocalEndPoint.Equals(client.Client?.LocalEndPoint)
                             && x.RemoteEndPoint.Equals(client.Client?.RemoteEndPoint)
          );

        return info?.State;
    }
}
