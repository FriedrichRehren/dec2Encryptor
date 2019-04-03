using IO = System.IO;
using System.Security;
using System.Text;
using System;

namespace dec2Encryptor
{
    /// <summary>
    /// Encrypt
    /// </summary>
    public static class Encrypt
    {
        /// <summary>
        /// Encrypt a String using the AES256 Algorythm
        /// </summary>
        /// <param name="input">Input String</param>
        /// <param name="password">The Password</param>
        /// <returns>Encrypted String</returns>
        public static string String(string input, SecureString password)
        {
            //Get Byte Array from String
            byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(input);

            //Get Encrypted Bytes
            byte[] bytesEncrypted = Algorythm.AES265.Encrypt(bytesToBeEncrypted, password);

            //Return Encrypted String
            return Convert.ToBase64String(bytesEncrypted);
        }

        /// <summary>
        /// Encrypt a String
        /// </summary>
        /// <param name="input">Input String</param>
        /// <param name="password">The Password</param>
        /// <param name="algorythm">The Algorythm to use</param>
        /// <returns>Encrypted String</returns>
        public static string String(string input, SecureString password, Algorythms algorythm)
        {
            //Get Byte Array from String
            byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(input);

            //Get Decrypted Bytes with respect of choosen Algorythm
            byte[] bytesEncrypted = null;
            switch (algorythm)
            {
                case Algorythms.AES128:
                    bytesEncrypted = Algorythm.AES128.Encrypt(bytesToBeEncrypted, password);
                    break;

                case Algorythms.AES160:
                    bytesEncrypted = Algorythm.AES160.Encrypt(bytesToBeEncrypted, password);
                    break;

                case Algorythms.AES192:
                    bytesEncrypted = Algorythm.AES192.Encrypt(bytesToBeEncrypted, password);
                    break;

                case Algorythms.AES224:
                    bytesEncrypted = Algorythm.AES224.Encrypt(bytesToBeEncrypted, password);
                    break;

                case Algorythms.AES256:
                    bytesEncrypted = Algorythm.AES265.Encrypt(bytesToBeEncrypted, password);
                    break;

                case Algorythms.RSA2048:
                    bytesEncrypted = Algorythm.RSA2048.Encrypt(bytesToBeEncrypted, password);
                    break;

                default:
                    bytesEncrypted = Algorythm.AES265.Encrypt(bytesToBeEncrypted, password);
                    break;
            }

            //Return Encrypted String
            return Convert.ToBase64String(bytesEncrypted);
        }

        /// <summary>
        /// Encrypt a String using the AES256 Algorythm
        /// </summary>
        /// <param name="input">Input String</param>
        /// <param name="password">The Password</param>
        /// <returns>Encrypted String</returns>
        public static string String(string input, string password)
        {
            //Get Byte Arrays from Strings
            byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(input);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            //Get Encrypted Bytes
            byte[] bytesEncrypted = Algorythm.AES265.Encrypt(bytesToBeEncrypted, passwordBytes);

            //Return Encrypted String
            return Convert.ToBase64String(bytesEncrypted);
        }

        /// <summary>
        /// Encrypt a String
        /// </summary>
        /// <param name="input">Input String</param>
        /// <param name="password">The Password</param>
        /// <param name="algorythm">The Algorythm to use</param>
        /// <returns>Encrypted String</returns>
        public static string String(string input, string password, Algorythms algorythm)
        {
            //Get Byte Arrays from Strings
            byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(input);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            //Get Decrypted Bytes with respect of choosen Algorythm
            byte[] bytesEncrypted = null;
            switch (algorythm)
            {
                case Algorythms.AES128:
                    bytesEncrypted = Algorythm.AES128.Encrypt(bytesToBeEncrypted, passwordBytes);
                    break;

                case Algorythms.AES160:
                    bytesEncrypted = Algorythm.AES160.Encrypt(bytesToBeEncrypted, passwordBytes);
                    break;

                case Algorythms.AES192:
                    bytesEncrypted = Algorythm.AES192.Encrypt(bytesToBeEncrypted, passwordBytes);
                    break;

                case Algorythms.AES224:
                    bytesEncrypted = Algorythm.AES224.Encrypt(bytesToBeEncrypted, passwordBytes);
                    break;

                case Algorythms.AES256:
                    bytesEncrypted = Algorythm.AES265.Encrypt(bytesToBeEncrypted, passwordBytes);
                    break;

                case Algorythms.RSA2048:
                    bytesEncrypted = Algorythm.RSA2048.Encrypt(bytesToBeEncrypted, passwordBytes);
                    break;

                default:
                    bytesEncrypted = Algorythm.AES265.Encrypt(bytesToBeEncrypted, passwordBytes);
                    break;
            }

            //Return Encrypted String
            return Convert.ToBase64String(bytesEncrypted);
        }

        /// <summary>
        /// Encrypt a Stream using the AES256 Algorythm
        /// </summary>
        /// <param name="input">Input Stream</param>
        /// <param name="password">The Password</param>
        /// <returns>Encrypted Stream</returns>
        public static IO.Stream Stream(IO.Stream input, SecureString password)
        {
            //Return Encrypted Stream
            return Algorythm.AES265.Encrypt(input, password);
        }

        /// <summary>
        /// Encrypt a Stream
        /// </summary>
        /// <param name="input">Input Stream</param>
        /// <param name="password">The Password</param>
        /// <param name="algorythm">The Algorythm to use</param>
        /// <returns>Encrypted Stream</returns>
        public static IO.Stream Stream(IO.Stream input, SecureString password, Algorythms algorythm)
        {
            //Return Encrypted Stream with respect of choosen Algorythm
            switch (algorythm)
            {
                case Algorythms.AES128:
                    return Algorythm.AES128.Encrypt(input, password);

                case Algorythms.AES160:
                    return Algorythm.AES160.Encrypt(input, password);

                case Algorythms.AES192:
                    return Algorythm.AES192.Encrypt(input, password);

                case Algorythms.AES224:
                    return Algorythm.AES224.Encrypt(input, password);

                case Algorythms.AES256:
                    return Algorythm.AES265.Encrypt(input, password);

                case Algorythms.RSA2048:
                    return Algorythm.RSA2048.Encrypt(input, password);

                default:
                    return Algorythm.AES265.Encrypt(input, password);
            }
        }

        /// <summary>
        /// Encrypt a Stream using the AES256 Algorythm
        /// </summary>
        /// <param name="input">Input Stream</param>
        /// <param name="password">The Password</param>
        /// <returns>Encrypted Stream</returns>
        public static IO.Stream Stream(IO.Stream input, string password)
        {
            //Get Byte Array from String
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            //Return Encrypted Stream
            return Algorythm.AES265.Encrypt(input, passwordBytes);
        }

        /// <summary>
        /// Encrypt a Stream using the AES256 Algorythm
        /// </summary>
        /// <param name="input">Input Stream</param>
        /// <param name="password">The Password</param>
        /// <param name="algorythm">The Algorythm to use</param>
        /// <returns>Encrypted Stream</returns>
        public static IO.Stream Stream(IO.Stream input, string password, Algorythms algorythm)
        {
            //Get Byte Array from String
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            //Return Encrypted Stream with respect of choosen Algorythm
            switch (algorythm)
            {
                case Algorythms.AES128:
                    return Algorythm.AES128.Encrypt(input, passwordBytes);

                case Algorythms.AES160:
                    return Algorythm.AES160.Encrypt(input, passwordBytes);

                case Algorythms.AES192:
                    return Algorythm.AES192.Encrypt(input, passwordBytes);

                case Algorythms.AES224:
                    return Algorythm.AES224.Encrypt(input, passwordBytes);

                case Algorythms.AES256:
                    return Algorythm.AES265.Encrypt(input, passwordBytes);

                case Algorythms.RSA2048:
                    return Algorythm.RSA2048.Encrypt(input, passwordBytes);

                default:
                    return Algorythm.AES265.Encrypt(input, passwordBytes);
            }
        }

        /// <summary>
        /// Encrypt a File using the AES256 Algorythm
        /// </summary>
        /// <param name="file">Path of Input File</param>
        /// <param name="password">The Password</param>
        /// <param name="outputFile">Path of Output File</param>
        public static void File(string file, SecureString password, string outputFile)
        {
            //Get Byte Array from File
            byte[] bytesToBeEncrypted = IO.File.ReadAllBytes(file);

            //Get Encrypted Bytes
            byte[] bytesEncrypted = Algorythm.AES265.Encrypt(bytesToBeEncrypted, password);

            //Write Encrypted Byte Array
            IO.File.WriteAllBytes(outputFile, bytesEncrypted);
        }

        /// <summary>
        /// Encrypt a File
        /// </summary>
        /// <param name="file">Path of Input File</param>
        /// <param name="password">The Password</param>
        /// <param name="algorythm">The Algorythm to use</param>
        /// <param name="outputFile">Path of Output File</param>
        public static void File(string file, SecureString password, string outputFile, Algorythms algorythm)
        {
            //Get Byte Array from File
            byte[] bytesToBeEncrypted = IO.File.ReadAllBytes(file);

            //Get Decrypted Bytes with respect of choosen Algorythm
            byte[] bytesEncrypted = null;
            switch (algorythm)
            {
                case Algorythms.AES128:
                    bytesEncrypted = Algorythm.AES128.Encrypt(bytesToBeEncrypted, password);
                    break;

                case Algorythms.AES160:
                    bytesEncrypted = Algorythm.AES160.Encrypt(bytesToBeEncrypted, password);
                    break;

                case Algorythms.AES192:
                    bytesEncrypted = Algorythm.AES192.Encrypt(bytesToBeEncrypted, password);
                    break;

                case Algorythms.AES224:
                    bytesEncrypted = Algorythm.AES224.Encrypt(bytesToBeEncrypted, password);
                    break;

                case Algorythms.AES256:
                    bytesEncrypted = Algorythm.AES265.Encrypt(bytesToBeEncrypted, password);
                    break;

                case Algorythms.RSA2048:
                    bytesEncrypted = Algorythm.RSA2048.Encrypt(bytesToBeEncrypted, password);
                    break;

                default:
                    bytesEncrypted = Algorythm.AES265.Encrypt(bytesToBeEncrypted, password);
                    break;
            }

            //Write Encrypted Byte Array
            IO.File.WriteAllBytes(outputFile, bytesEncrypted);
        }

        /// <summary>
        /// Encrypt a File using the AES256 Algorythm
        /// </summary>
        /// <param name="file">Path of Input File</param>
        /// <param name="password">The Password</param>
        /// <param name="outputFile">Path of Output File</param>
        public static void File(string file, string password, string outputFile)
        {
            //Get Byte Array from File
            byte[] bytesToBeEncrypted = IO.File.ReadAllBytes(file);
            //Get Byte Array from String
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            //Get Encrypted Bytes
            byte[] bytesEncrypted = Algorythm.AES265.Encrypt(bytesToBeEncrypted, passwordBytes);

            //Write Encrypted Byte Array
            IO.File.WriteAllBytes(outputFile, bytesEncrypted);
        }

        /// <summary>
        /// Encrypt a File
        /// </summary>
        /// <param name="file">Path of Input File</param>
        /// <param name="password">The Password</param>
        /// <param name="algorythm">The Algorythm to use</param>
        /// <param name="outputFile">Path of Output File</param>
        public static void File(string file, string password, string outputFile, Algorythms algorythm)
        {
            //Get Byte Array from File
            byte[] bytesToBeEncrypted = IO.File.ReadAllBytes(file);
            //Get Byte Array from String
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            //Get Decrypted Bytes with respect of choosen Algorythm
            byte[] bytesEncrypted = null;
            switch (algorythm)
            {
                case Algorythms.AES128:
                    bytesEncrypted = Algorythm.AES128.Encrypt(bytesToBeEncrypted, passwordBytes);
                    break;

                case Algorythms.AES160:
                    bytesEncrypted = Algorythm.AES160.Encrypt(bytesToBeEncrypted, passwordBytes);
                    break;

                case Algorythms.AES192:
                    bytesEncrypted = Algorythm.AES192.Encrypt(bytesToBeEncrypted, passwordBytes);
                    break;

                case Algorythms.AES224:
                    bytesEncrypted = Algorythm.AES224.Encrypt(bytesToBeEncrypted, passwordBytes);
                    break;

                case Algorythms.AES256:
                    bytesEncrypted = Algorythm.AES265.Encrypt(bytesToBeEncrypted, passwordBytes);
                    break;

                case Algorythms.RSA2048:
                    bytesEncrypted = Algorythm.RSA2048.Encrypt(bytesToBeEncrypted, passwordBytes);
                    break;

                default:
                    bytesEncrypted = Algorythm.AES265.Encrypt(bytesToBeEncrypted, passwordBytes);
                    break;
            }

            //Write Encrypted Byte Array
            IO.File.WriteAllBytes(outputFile, bytesEncrypted);
        }

        /// <summary>
        /// Encrypt a Byte Array using the AES256 Algorythm
        /// </summary>
        /// <param name="input">Input Byte Arraý</param>
        /// <param name="password">The Password</param>
        /// <returns>Encrypted Byte Array</returns>
        public static byte[] ByteArray(byte[] input, SecureString password)
        {
            //Return the Encrypted Bytes
            return Algorythm.AES265.Encrypt(input, password);
        }

        /// <summary>
        /// Encrypt a Byte Array
        /// </summary>
        /// <param name="input">Input Byte Arraý</param>
        /// <param name="password">The Password</param>
        /// <param name="algorythm">The Algorythm to use</param>
        /// <returns>Encrypted Byte Array</returns>
        public static byte[] ByteArray(byte[] input, SecureString password, Algorythms algorythm)
        {
            //Return Encrypted Byte Array with respect of choosen Algorythm
            switch (algorythm)
            {
                case Algorythms.AES128:
                    return Algorythm.AES128.Encrypt(input, password);

                case Algorythms.AES160:
                    return Algorythm.AES160.Encrypt(input, password);

                case Algorythms.AES192:
                    return Algorythm.AES192.Encrypt(input, password);

                case Algorythms.AES224:
                    return Algorythm.AES224.Encrypt(input, password);

                case Algorythms.AES256:
                    return Algorythm.AES265.Encrypt(input, password);

                case Algorythms.RSA2048:
                    return Algorythm.RSA2048.Encrypt(input, password);

                default:
                    return Algorythm.AES265.Encrypt(input, password);
            }
        }

        /// <summary>
        /// Encrypt a Byte Array using the AES256 Algorythm
        /// </summary>
        /// <param name="input">Input Byte Arraý</param>
        /// <param name="password">The Password</param>
        /// <returns>Encrypted Byte Array</returns>
        public static byte[] ByteArray(byte[] input, string password)
        {
            //Get Byte Array from String
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            //Return the Encrypted Byte Array
            return Algorythm.AES265.Encrypt(input, passwordBytes);
        }

        /// <summary>
        /// Encrypt a Byte Array
        /// </summary>
        /// <param name="input">Input Byte Arraý</param>
        /// <param name="password">The Password</param>
        /// <param name="algorythm">The Algorythm to use</param>
        /// <returns>Encrypted Byte Array</returns>
        public static byte[] ByteArray(byte[] input, string password, Algorythms algorythm)
        {
            //Get Byte Array from String
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            //Return Encrypted Byte Array with respect of choosen Algorythm
            switch (algorythm)
            {
                case Algorythms.AES128:
                    return Algorythm.AES128.Encrypt(input, passwordBytes);

                case Algorythms.AES160:
                    return Algorythm.AES160.Encrypt(input, passwordBytes);

                case Algorythms.AES192:
                    return Algorythm.AES192.Encrypt(input, passwordBytes);

                case Algorythms.AES224:
                    return Algorythm.AES224.Encrypt(input, passwordBytes);

                case Algorythms.AES256:
                    return Algorythm.AES265.Encrypt(input, passwordBytes);

                case Algorythms.RSA2048:
                    return Algorythm.RSA2048.Encrypt(input, passwordBytes);

                default:
                    return Algorythm.AES265.Encrypt(input, passwordBytes);
            }
        }
    }
}