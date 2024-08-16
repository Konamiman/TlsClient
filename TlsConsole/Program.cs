using Konamiman.TlsClient;
using Konamiman.TlsClient.DataTransport;
using System.Text;
using static System.Console;
using ConnectionState = Konamiman.TlsClient.Enums.ConnectionState;

namespace Konamiman.TlsConsole;

class Program
{
    static bool keepRunning = true;

    public static void Main(string[] args)
    {
        if(args.Length == 0) {
            WriteLine("TCP based TLS 1.3 console");
            WriteLine("Usage: TLSCON <host> [<port>]");
            return;
        }

        var host = args[0];
        int port = args.Length > 1 ? int.Parse(args[1]) : 443;

        keepRunning = true;
        Console.CancelKeyPress += Console_CancelKeyPress;
        WriteLine("--- Opening connection...");

        var tcpTransport = new TcpDataTransport(host, port);
        try {
            tcpTransport.Connect();
        }
        catch(Exception ex) {
            WriteLine($"*** Connection failed: {ex.Message}");
            return;
        }

        var connection = new TlsClientConnection(tcpTransport, null, host);

        while(connection.State < ConnectionState.Established) ;
        WriteLine("--- Connected! Typed lines will be sent when pressing ENTER");

        while(keepRunning) {
            if(KeyAvailable) {
                var line = ReadLine();
                connection.SendApplicationData(Encoding.ASCII.GetBytes(line + "\r\n"));
            }

            var incomingData = connection.GetApplicationData(1024);
            if(incomingData.Length != 0) {
                WriteLine(Encoding.ASCII.GetString(incomingData));
            }

            keepRunning &= connection.State == ConnectionState.Established;
        }

        if(connection.ErrorMessage is not null) {
            WriteLine($"--- Something went wrong: {connection.ErrorMessage}");
            if(connection.AlertSent is not null) {
                WriteLine($"---Alert sent: {connection.AlertSent}");
            }
        }
        else if(connection.State != ConnectionState.Established) {
            WriteLine("--- Connection closed by peer");
            if(connection.AlertReceived is not null) {
                WriteLine($"--- TLS alert received: {connection.AlertReceived}");
            }
        }

        connection.Close();
    }

    static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
    {
        Console.WriteLine("--- Connection closed locally");
        keepRunning = false;
        e.Cancel = true;
    }
}