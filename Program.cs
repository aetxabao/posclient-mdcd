using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.IO;
using System.Xml.Serialization;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace PosClient
{
    public class Message
    {
        public string From { get; set; }
        public string To { get; set; }
        public string Msg { get; set; }
        public string Stamp { get; set; }

        public override string ToString()
        {
            return $"From: {From}\nTo: {To}\n{Msg}\nStamp: {Stamp}";
        }
    }

    public class Client
    {
        public static string ip = "127.0.0.1";
        public static int port = 14300;
        public static int TAM = 8192;

        // Para los servicios de criptografía
        public static MDCD mdcd = new MDCD();
        // Para guardar la clave pública del servidor
        public static string srvPubKey;
        // Para el propio cliente
        public static RSACryptoServiceProvider rsa = mdcd.rsa;

        // Para verificar mensajes del servidor
        public static bool Verify(Message m)
        {
            //Lo mismo que en el servidor pero en Vez de pubKey Utilizamos la servPubKey
            //que quiere decir la clave pública del servidor
            try
            {
                string txt = m.From + m.To + m.Msg;
                string sha = X.ShaHash(txt);
                return X.VerifyData(sha, m.Stamp, srvPubKey);
            }
            catch (Exception)
            {
                return false;
            }

        }

        //Para firmar mensajes
        public static void Sign(ref Message m)
        {
            //Ya que en el servidor tambien firma y me ha
            // parecido que firmar se hacen igual tanto en servidor como en cliente
            string txt = m.From + m.To + m.Msg;
            string sha = X.ShaHash(txt);
            m.Stamp = X.SignedData(sha, rsa);
        }

        public static IPAddress GetLocalIpAddress()
        {
            List<IPAddress> ipAddressList = new List<IPAddress>();
            IPHostEntry ipHostInfo = Dns.GetHostEntry(Dns.GetHostName());
            IPAddress ipAddress = ipHostInfo.AddressList[0];
            int t = ipHostInfo.AddressList.Length;
            string ip;
            for (int i = 0; i < t; i++)
            {
                ip = ipHostInfo.AddressList[i].ToString();
                if (ip.Contains(".") && !ip.Equals("127.0.0.1")) ipAddressList.Add(ipHostInfo.AddressList[i]);
            }
            if (ipAddressList.Count > 0)
            {
                return ipAddressList[0];//devuelve la primera posible
            }
            return null;
        }

        public static void ReadServerIpPort()
        {
            string s;
            System.Console.WriteLine("Datos del servidor: ");
            string defIp = GetLocalIpAddress().ToString();
            System.Console.Write("Dir. IP [{0}]: ", defIp);
            s = Console.ReadLine();
            if ((s.Length > 0) && (s.Replace(".", "").Length == s.Length - 3))
            {
                ip = s;
            }
            else
            {
                ip = defIp;
            }
            System.Console.Write("PUERTO [{0}]: ", port);
            s = Console.ReadLine();
            if (Int32.TryParse(s, out int i))
            {
                port = i;
            }
        }

        public static void PrintOptionMenu()
        {
            System.Console.WriteLine("====================");
            System.Console.WriteLine("        MENU        ");
            System.Console.WriteLine("====================");
            System.Console.WriteLine("0: Salir");
            System.Console.WriteLine("1: Chequear correo");
            System.Console.WriteLine("2: Obtener mensaje");
            System.Console.WriteLine("3: Escribir mensaje");
            System.Console.WriteLine("4: MyDeCoDer ");
            System.Console.WriteLine("5: Enviar clave pub.");
        }

        public static int ReadOption()
        {
            string s = null;
            while (true)
            {
                System.Console.Write("Opción [0-5]: ");
                s = Console.ReadLine();
                if (Int32.TryParse(s, out int i))
                {
                    if ((i >= 0) && (i <= 5))
                    {
                        return i;
                    }
                }
            }
        }

        public static Socket Connect()
        {
            IPAddress ipAddress = System.Net.IPAddress.Parse(ip);
            IPEndPoint remoteEP = new IPEndPoint(ipAddress, port);

            Socket socket = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            socket.Connect(remoteEP);

            return socket;
        }

        public static void Disconnect(Socket socket)
        {
            socket.Shutdown(SocketShutdown.Both);
            socket.Close();
        }

        public static void Send(Socket socket, Message message)
        {
            XmlSerializer serializer = new XmlSerializer(typeof(Message));
            Stream stream = new MemoryStream();
            serializer.Serialize(stream, message);
            byte[] byteData = ((MemoryStream)stream).ToArray();
            // string xml = Encoding.ASCII.GetString(byteData, 0, byteData.Length);
            // Console.WriteLine(xml);//Imprime el texto enviado
            int bytesSent = socket.Send(byteData);
        }

        public static Message Receive(Socket socket)
        {
            byte[] bytes = new byte[TAM];
            int bytesRec = socket.Receive(bytes);
            string xml = Encoding.ASCII.GetString(bytes, 0, bytesRec);
            // Console.WriteLine(xml);//Imprime el texto recibido
            byte[] byteArray = Encoding.ASCII.GetBytes(xml);
            MemoryStream stream = new MemoryStream(byteArray);
            Message response = (Message)new XmlSerializer(typeof(Message)).Deserialize(stream);
            return response;
        }

        public static void Process(int option)
        {
            switch (option)
            {
                case 1:
                    ChequearCorreo();
                    break;
                case 2:
                    ObtenerMensaje();
                    break;
                case 3:
                    EscribirMensaje();
                    break;
                case 4:
                    //TODO: Acceder a las opciones de MDCD mostrando el menú critográfico
                    //Ya que queremos que se ejecuten todas sus opciones , si no las iríamos eligiendo una a una
                    //Ya que si hacemos control espacio nos salen todas las opciones por separado y el metodo Run 
                    //que es para ejecutar todas
                    mdcd.Run();
                    break;
                case 5:
                    EnviarClavePub();
                    break;
            }
        }

        public static void EnviarClavePub()
        {
            System.Console.WriteLine("--------------------");
            System.Console.WriteLine("5: Enviar clave pub.");
            System.Console.WriteLine("--------------------");
            System.Console.Write("From: ");
            string f = Console.ReadLine();

            Socket socket = Connect();
            //TODO: Crear un mensaje con la clave pública del cliente firmado y enviarlo
            string to = "0";
            string msg = X.RsaGetPubParsXml(rsa);
            Message mensaje = new Message { From = f, To = to, Msg = "PUBKEY " + msg, Stamp = "Client" };
            Sign(ref mensaje);
            Send(socket, mensaje);


            System.Console.WriteLine("....................");
            Message response = Receive(socket);
            if (!response.Msg.StartsWith("ERROR"))
            {
                //TODO: Extraer la clave pública del servidor del mensaje y verificar el mensaje de respuesta
                //si no se puede verificar la respuesta mostrar en consola "ERROR server VALIDATION"
                //y no asignar a srvPubKey la clave pública del servidor recibida

                if (Verify(response))
                {
                    srvPubKey = response.Msg;
                }
                else
                {
                    System.Console.WriteLine("Error de verificacion del mensaje de respuesta ");
                }

            }
            Console.WriteLine(response);
            Disconnect(socket);

        }

        public static void ChequearCorreo()
        {
            System.Console.WriteLine("--------------------");
            System.Console.WriteLine("1: Chequear correo  ");
            System.Console.WriteLine("--------------------");
            System.Console.Write("From: ");
            string f = Console.ReadLine();

            Socket socket = Connect();
            Message request = new Message { From = f, To = "0", Msg = "LIST", Stamp = "Client" };
            //TODO: Firmar mensaje que solicita lista de correos
            //Con esto llamamos al mensaje que lo tenemos justo arriba (request) y lo firmarmo 
            Sign(ref request);
            Send(socket, request);
            System.Console.WriteLine("....................");
            Message response = Receive(socket);
            //TODO: Verificar el mensaje de respuesta a LIST
            //si no se puede verificar la respuesta mostrar en consola "ERROR server VALIDATION"
            //Supongo que hay que verificar al igual que en metodo anterior lo cual sera la misma estructura

            if (!Verify(response))
            {
                System.Console.WriteLine("ERROR server VALIDATION");
            }
            else
            {
                srvPubKey = response.Msg;
            }

            Console.WriteLine(response);
            Disconnect(socket);
        }

        public static void ObtenerMensaje()
        {
            System.Console.WriteLine("--------------------");
            System.Console.WriteLine("2: Obtener mensaje  ");
            System.Console.WriteLine("--------------------");
            System.Console.Write("From: ");
            string f = Console.ReadLine();
            System.Console.Write("Num.: ");
            string n = Console.ReadLine();

            Socket socket = Connect();
            Message request = new Message { From = f, To = "0", Msg = "RETR " + n, Stamp = "Client" };
            //TODO: Firmar mensaje que solicita un correo
            Sign(ref request);
            Send(socket, request);
            System.Console.WriteLine("....................");
            Message response = Receive(socket);
            Console.WriteLine(response);
            Disconnect(socket);
        }

        public static void EscribirMensaje()
        {
            System.Console.WriteLine("--------------------");
            System.Console.WriteLine("3: Escribir mensaje ");
            System.Console.WriteLine("--------------------");
            System.Console.Write("From: ");
            string f = Console.ReadLine();
            System.Console.Write("To: ");
            string t = Console.ReadLine();
            System.Console.Write("Msg: ");
            string m = Console.ReadLine();

            Socket socket = Connect();
            Message request = new Message { From = f, To = t, Msg = m, Stamp = "Client" };
            //TODO: Firmar mensaje que se envia para otro cliente
            Sign(ref request);
            Send(socket, request);
            System.Console.WriteLine("....................");
            Message response = Receive(socket);
            //TODO: Verificar el mensaje de respuesta de recepción
            //si no se puede verificar la respuesta mostrar en consola "ERROR server VALIDATION"

            if (!Verify(response))
            {
                System.Console.WriteLine("ERROR server VALIDATION");
            }
            else
            {
                srvPubKey = response.Msg;
            }



            Console.WriteLine(response);
            Disconnect(socket);
        }

        public static int Main(String[] args)
        {
            ReadServerIpPort();
            while (true)
            {
                PrintOptionMenu();
                int opt = ReadOption();
                if (opt == 0) break;
                Process(opt);
            }
            System.Console.WriteLine("FIN.");
            return 0;
        }
    }
}