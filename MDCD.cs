using System;
using System.Security.Cryptography;

namespace PosClient
{
    public class MDCD
    {
        public RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(3072);

        public void PrintOptionMenu()
        {
            System.Console.WriteLine(@"=========================
         MyDeCoDer       
=========================
0. Exit
1. Codificar AES
2. Decodificar AES
3. RSA Pub key
4. Codificar RSA
5. Decodificar RSA
6. Firmar
7. Comprobar firma
8. Hash SHA 256
9. Random string");
        }

        public int ReadOption()
        {
            string s = null;
            while (true)
            {
                System.Console.Write("Opción [0-9]: ");
                s = Console.ReadLine();
                if (Int32.TryParse(s, out int i))
                {
                    if ((i >= 0) && (i <= 9))
                    {
                        return i;
                    }
                }
            }
        }

        public void Process(int option)
        {
            switch (option)
            {
                case 1:
                    CodificarAes();
                    break;
                case 2:
                    DecodificarAes();
                    break;
                case 3:
                    RsaPubKey();
                    break;
                case 4:
                    CodificarRsa();
                    break;
                case 5:
                    DecodificarRsa();
                    break;
                case 6:
                    Firmar();
                    break;
                case 7:
                    ComprobarFirma();
                    break;
                case 8:
                    HashSha();
                    break;
                case 9:
                    RndStr();
                    break;
            }
        }

        public void CodificarAes()
        {
            System.Console.WriteLine("-----------------------");
            System.Console.WriteLine("1: Codificar AES");
            System.Console.WriteLine("-----------------------");
            System.Console.Write("Mensaje    : ");
            string msg = Console.ReadLine();
            System.Console.Write("Password   : ");
            string pwd = Console.ReadLine();
            System.Console.WriteLine(".......................");
            string iv = "";
            try
            {
                string encripted = X.AesEncrypt(msg, pwd, out iv);
                System.Console.WriteLine("Encrypted  : {0}", encripted);
                System.Console.WriteLine("IV         : {0}", iv);
            }
            catch (Exception)
            {
                System.Console.WriteLine("ERROR");
            }
        }

        public void DecodificarAes()
        {
            System.Console.WriteLine("-----------------------");
            System.Console.WriteLine("2: Decodificar AES");
            System.Console.WriteLine("-----------------------");
            System.Console.Write("Encriptado : ");
            string enc = Console.ReadLine();
            System.Console.Write("Password   : ");
            string pwd = Console.ReadLine();
            System.Console.Write("IV         : ");
            string sal = Console.ReadLine();
            System.Console.WriteLine(".......................");
            try
            {
                string plaintext = X.AesDecrypt(enc, pwd, sal);
                System.Console.WriteLine("Mensaje    : {0}", plaintext);
            }
            catch (Exception)
            {
                System.Console.WriteLine("ERROR");
            }
        }

        public void RsaPubKey()
        {
            System.Console.WriteLine("-----------------------");
            System.Console.WriteLine("3. RSA Pub key");
            System.Console.WriteLine("-----------------------");
            try
            {
                string xml = X.RsaGetPubParsXml(rsa);
                System.Console.WriteLine(xml);
            }
            catch (Exception)
            {
                System.Console.WriteLine("ERROR");
            }
        }

        public void CodificarRsa()
        {
            System.Console.WriteLine("-----------------------");
            System.Console.WriteLine("4: Codificar RSA");
            System.Console.WriteLine("-----------------------");
            System.Console.WriteLine("Mensaje    : ");
            string text = Console.ReadLine();
            System.Console.WriteLine("PubKey(xml): ");
            string pubParsXml = Console.ReadLine();
            System.Console.WriteLine(".......................");
            try
            {
                string encripted = X.RsaEncrypt(text, pubParsXml);
                System.Console.WriteLine(encripted);
            }
            catch (Exception)
            {
                System.Console.WriteLine("ERROR");
            }
        }

        public void DecodificarRsa()
        {
            System.Console.WriteLine("-----------------------");
            System.Console.WriteLine("5: Decodificar RSA");
            System.Console.WriteLine("-----------------------");
            System.Console.WriteLine("Encriptado : ");
            string enc = Console.ReadLine();
            System.Console.WriteLine(".......................");
            try
            {
                string plaintext = X.RsaDecrypt(enc, rsa);
                System.Console.WriteLine(plaintext);
            }
            catch (Exception)
            {
                System.Console.WriteLine("ERROR");
            }
        }
        public void Firmar()
        {
            System.Console.WriteLine("-----------------------");
            System.Console.WriteLine("6: Firmar");
            System.Console.WriteLine("-----------------------");
            System.Console.WriteLine("Mensaje    : ");
            string text = Console.ReadLine();
            System.Console.WriteLine(".......................");
            try
            {
                string signed = X.SignedData(text, rsa);
                System.Console.WriteLine(signed);
            }
            catch (Exception)
            {
                System.Console.WriteLine("ERROR");
            }
        }

        public void ComprobarFirma()
        {
            System.Console.WriteLine("-----------------------");
            System.Console.WriteLine("7: Comprobar firma");
            System.Console.WriteLine("-----------------------");
            System.Console.WriteLine("Mensaje    : ");
            string text = Console.ReadLine();
            System.Console.WriteLine("Firma      : ");
            string signedText = Console.ReadLine();
            System.Console.WriteLine("PubKey(xml): ");
            string pubParsXml = Console.ReadLine();
            System.Console.WriteLine(".......................");
            try
            {
                bool b = X.VerifyData(text, signedText, pubParsXml);
                System.Console.WriteLine(b);
            }
            catch (Exception)
            {
                System.Console.WriteLine("ERROR");
            }
        }

        public void HashSha()
        {
            System.Console.WriteLine("-----------------------");
            System.Console.WriteLine("8: Hash SHA 256");
            System.Console.WriteLine("-----------------------");
            System.Console.WriteLine("Mensaje    : ");
            string text = Console.ReadLine();
            System.Console.WriteLine(".......................");
            try
            {
                string hash = X.ShaHash(text);
                System.Console.WriteLine(hash);
            }
            catch (Exception)
            {
                System.Console.WriteLine("ERROR");
            }
        }

        public void RndStr()
        {
            System.Console.WriteLine("-----------------------");
            System.Console.WriteLine("9. Random string");
            System.Console.WriteLine("-----------------------");
            System.Console.Write("Longitud   : ");
            string s = System.Console.ReadLine();
            if (Int32.TryParse(s, out int i))
            {
                if (i > 0)
                {
                    System.Console.WriteLine(".......................");
                    string text = X.RandomString(i);
                    System.Console.WriteLine(text);
                }
            }
        }

        public void Run()
        {

            while (true)
            {
                PrintOptionMenu();
                int opt = ReadOption();
                if (opt == 0) break;
                Process(opt);
            }
        }

    }
}

