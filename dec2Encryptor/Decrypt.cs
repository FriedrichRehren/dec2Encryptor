using IO = System.IO;
using System.Security;
using System.Text;

namespace dec2Encryptor
{
    /// <summary>
    /// Decrypt
    /// </summary>
    public class Decrypt
    {
        /// <summary>
        /// Decrypt a String using the AES256 Algorythm
        /// /// </summary>
        /// <param name="input">Input String</param>
        /// <param name="password">The Password</param>
        /// <returns>Decrypted String</returns>
        public static string String(string input, SecureString password)
        {
            //Get Byte Array from String
            byte[] bytesToBeDecrypted = Encoding.UTF8.GetBytes(input);

            //Get Decrypted Bytes
            byte[] bytesDecrypted = Algorythm.AES265.Decrypt(bytesToBeDecrypted, password);

            //Return Decrypted String
            return Encoding.UTF8.GetString(bytesDecrypted);
        }

        /// <summary>
        /// Decrypt a String
        /// </summary>
        /// <param name="input">Input String</param>
        /// <param name="password">The Password</param>
        /// <param name="algorythm">The Algorythm to use</param>
        /// <returns>Decrypted String</returns>
        public static string String(string input, SecureString password, Algorythms algorythm)
        {
            //Get Byte Array from String
            byte[] bytesToBeDecrypted = Encoding.UTF8.GetBytes(input);

            //Get Decrypted Bytes with respect of choosen Algorythm
            byte[] bytesDecrypted = null;
            switch (algorythm)
            {
                case Algorythms.AES256:
                    bytesDecrypted = Algorythm.AES265.Decrypt(bytesToBeDecrypted, password);
                    break;

                default:
                    bytesDecrypted = Algorythm.AES265.Decrypt(bytesToBeDecrypted, password);
                    break;
            }

            //Return Decrypted String
            return Encoding.UTF8.GetString(bytesDecrypted);
        }

        /// <summary>
        /// Decrypt a String using the AES256 Algorythm
        /// </summary>
        /// <param name="input">Input String</param>
        /// <param name="password">The Password</param>
        /// <returns>Decrypted String</returns>
        public static string String(string input, string password)
        {
            //Get Byte Arrays from Strings
            byte[] bytesToBeDecrypted = Encoding.UTF8.GetBytes(input);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            //Get Decrypted Bytes
            byte[] bytesDecrypted = Algorythm.AES265.Decrypt(bytesToBeDecrypted, passwordBytes);

            //Return Decrypted String
            return Encoding.UTF8.GetString(bytesDecrypted);
        }

        /// <summary>
        /// Decrypt a String
        /// </summary>
        /// <param name="input">Input String</param>
        /// <param name="password">The Password</param>
        /// <param name="algorythm">The Algorythm to use</param>
        /// <returns>Decrypted String</returns>
        public static string String(string input, string password, Algorythms algorythm)
        {
            //Get Byte Arrays from Strings
            byte[] bytesToBeDecrypted = Encoding.UTF8.GetBytes(input);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            //Get Decrypted Bytes with respect of choosen Algorythm
            byte[] bytesDecrypted = null;
            switch (algorythm)
            {
                case Algorythms.AES256:
                    bytesDecrypted = Algorythm.AES265.Decrypt(bytesToBeDecrypted, passwordBytes);
                    break;

                default:
                    bytesDecrypted = Algorythm.AES265.Decrypt(bytesToBeDecrypted, passwordBytes);
                    break;
            }

            //Return Decrypted String
            return Encoding.UTF8.GetString(bytesDecrypted);
        }

        /// <summary>
        /// Decrypt a Stream using the AES256 Algorythm
        /// </summary>
        /// <param name="input">Input Stream</param>
        /// <param name="password">The Password</param>
        /// <returns>Decrypted Stream</returns>
        public static IO.Stream Stream(IO.Stream input, SecureString password)
        {
            //Return Encrypted Stream
            return Algorythm.AES265.Decrypt(input, password);
        }

        /// <summary>
        /// Decrypt a Stream
        /// </summary>
        /// <param name="input">Input Stream</param>
        /// <param name="password">The Password</param>
        /// <param name="algorythm">The Algorythm to use</param>
        /// <returns>Decrypted Stream</returns>
        public static IO.Stream Stream(IO.Stream input, SecureString password, Algorythms algorythm)
        {
            //Return Encrypted Stream with respect of choosen Algorythm
            switch (algorythm)
            {
                case Algorythms.AES256:
                    return Algorythm.AES265.Decrypt(input, password);

                default:
                    return Algorythm.AES265.Decrypt(input, password);
            }
        }

        /// <summary>
        /// Decrypt a Stream using the AES256 Algorythm
        /// </summary>
        /// <param name="input">Input Stream</param>
        /// <param name="password">The Password</param>
        /// <returns>Decrypted Stream</returns>
        public static IO.Stream Stream(IO.Stream input, string password)
        {
            //Get Byte Array from String
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            //Return Encrypted Stream
            return Algorythm.AES265.Decrypt(input, passwordBytes);
        }

        /// <summary>
        /// Decrypt a Stream
        /// </summary>
        /// <param name="input">Input Stream</param>
        /// <param name="password">The Password</param>
        /// <param name="algorythm">The Algorythm to use</param>
        /// <returns>Decrypted Stream</returns>
        public static IO.Stream Stream(IO.Stream input, string password, Algorythms algorythm)
        {
            //Get Byte Array from String
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            //Return Encrypted Stream with respect of choosen Algorythm
            switch (algorythm)
            {
                case Algorythms.AES256:
                    return Algorythm.AES265.Decrypt(input, passwordBytes);

                default:
                    return Algorythm.AES265.Decrypt(input, passwordBytes);
            }
        }

        /// <summary>
        /// Decrypt a File using the AES256 Algorythm
        /// </summary>
        /// <param name="file">&gt;The File to be Decrypted</param>
        /// <param name="password">The Password</param>
        /// <param name="outputFile">The Decrypted File</param>
        public static void File(string file, SecureString password, string outputFile)
        {
            //Get Byte Array from File
            byte[] bytesToBeDecrypted = IO.File.ReadAllBytes(file);

            //Get Decrypted Bytes
            byte[] bytesDecrypted = Algorythm.AES265.Decrypt(bytesToBeDecrypted, password);

            //Write Decrypted Byte Array
            IO.File.WriteAllBytes(outputFile, bytesDecrypted);
        }

        /// <summary>
        /// Decrypt a File
        /// </summary>
        /// <param name="file">&gt;The File to be Decrypted</param>
        /// <param name="password">The Password</param>
        /// <param name="outputFile">The Decrypted File</param>
        /// <param name="algorythm">The Algorythm to use</param>
        public static void File(string file, SecureString password, string outputFile, Algorythms algorythm)
        {
            //Get Byte Array from File
            byte[] bytesToBeDecrypted = IO.File.ReadAllBytes(file);

            //Get Decrypted Bytes with respect of choosen Algorythm
            byte[] bytesDecrypted = null;
            switch (algorythm)
            {
                case Algorythms.AES256:
                    bytesDecrypted = Algorythm.AES265.Decrypt(bytesToBeDecrypted, password);
                    break;

                default:
                    bytesDecrypted = Algorythm.AES265.Decrypt(bytesToBeDecrypted, password);
                    break;
            }

            //Write Decrypted Byte Array
            IO.File.WriteAllBytes(outputFile, bytesDecrypted);
        }

        /// <summary>
        /// Decrypt a File using the AES256 Algorythm
        /// </summary>
        /// <param name="file">&gt;The File to be Decrypted</param>
        /// <param name="password">The Password</param>
        /// <param name="outputFile">The Decrypted File</param>
        public static void File(string file, string password, string outputFile)
        {
            //Get Byte Array from File
            byte[] bytesToBeDecrypted = IO.File.ReadAllBytes(file);
            //Get Byte Array from String
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            //Get Decrypted Bytes
            byte[] bytesDecrypted = Algorythm.AES265.Decrypt(bytesToBeDecrypted, passwordBytes);

            //Write Decrypted Byte Array
            IO.File.WriteAllBytes(outputFile, bytesDecrypted);
        }

        /// <summary>
        /// Decrypt a File
        /// </summary>
        /// <param name="file">&gt;The File to be Decrypted</param>
        /// <param name="password">The Password</param>
        /// <param name="outputFile">The Decrypted File</param>
        /// <param name="algorythm">The Algorythm to use</param>
        public static void File(string file, string password, string outputFile, Algorythms algorythm)
        {
            //Get Byte Array from File
            byte[] bytesToBeDecrypted = IO.File.ReadAllBytes(file);
            //Get Byte Array from String
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            //Get Decrypted Bytes with respect of choosen Algorythm
            byte[] bytesDecrypted = null;
            switch (algorythm)
            {
                case Algorythms.AES256:
                    bytesDecrypted = Algorythm.AES265.Decrypt(bytesToBeDecrypted, passwordBytes);
                    break;

                default:
                    bytesDecrypted = Algorythm.AES265.Decrypt(bytesToBeDecrypted, passwordBytes);
                    break;
            }

            //Write Decrypted Byte Array
            IO.File.WriteAllBytes(outputFile, bytesDecrypted);
        }

        /// <summary>
        /// Decrypt a Byte Array using the AES256 Algorythm
        /// </summary>
        /// <param name="input">Input Byte Array</param>
        /// <param name="password">The Password</param>
        /// <returns>Decrypted Byte Array</returns>
        public static byte[] ByteArray(byte[] input, SecureString password)
        {
            //Return Decrypted Byte Array
            return Algorythm.AES265.Decrypt(input, password);
        }

        /// <summary>
        /// Decrypt a Byte Array
        /// </summary>
        /// <param name="input">Input Byte Array</param>
        /// <param name="password">The Password</param>
        /// <param name="algorythm">The Algorythm to use</param>
        /// <returns>Decrypted Byte Array</returns>
        public static byte[] ByteArray(byte[] input, SecureString password, Algorythms algorythm)
        {
            //Return Decrypted Byte Array with respect of choosen Algorythm
            switch (algorythm)
            {
                case Algorythms.AES256:
                    return Algorythm.AES265.Decrypt(input, password);

                default:
                    return Algorythm.AES265.Decrypt(input, password);
            }
        }

        /// <summary>
        /// Decrypt a Byte Array using the AES256 Algorythm
        /// </summary>
        /// <param name="input">Input Byte Array</param>
        /// <param name="password">The Password</param>
        /// <returns>Decrypted Byte Array</returns>
        public static byte[] ByteArray(byte[] input, string password)
        {
            //Get Byte Array from String
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            //Return Decrypted Byte Array
            return Algorythm.AES265.Decrypt(input, passwordBytes);
        }

        /// <summary>
        /// Decrypt a Byte Array
        /// </summary>
        /// <param name="input">Input Byte Array</param>
        /// <param name="password">The Password</param>
        /// <param name="algorythm">The Algorythm to use</param>
        /// <returns>Decrypted Byte Array</returns>
        public static byte[] ByteArray(byte[] input, string password, Algorythms algorythm)
        {
            //Get Byte Array from String
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            //Return Decrypted Byte Array with respect of choosen Algorythm
            switch (algorythm)
            {
                case Algorythms.AES256:
                    return Algorythm.AES265.Decrypt(input, passwordBytes);

                default:
                    return Algorythm.AES265.Decrypt(input, passwordBytes);
            }
        }
    }
}