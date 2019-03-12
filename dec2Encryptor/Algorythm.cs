using System.IO;
using System.Security.Cryptography;
using System.Security;
using System;
using System.Runtime.InteropServices;

namespace dec2Encryptor
{
    internal static class Algorythm
    {
        /// <summary>
        /// Default Salt used for Encryption
        /// </summary>
        private static byte[] _saltBytes = new byte[] { 6, 4, 4, 0, 6, 0, 6, 7, 1, 1, 3, 9, 7, 0, 8, 8 };

        internal static class AES265
        {
            /// <summary>
            /// The AES Algorythm to Encrypt Bytes using Password Byte Array
            /// </summary>
            /// <param name="inputBytes">Input Byte Array</param>
            /// <param name="passwordBytes">Password Byte Array</param>
            /// <returns>Encrypted Byte Array</returns>
            internal static byte[] Encrypt(byte[] inputBytes, byte[] passwordBytes)
            {
                try
                {
                    //SetUp Output Byte Array
                    byte[] encryptedBytes = null;

                    //SetUp Memory Stream
                    using (MemoryStream mStream = new MemoryStream())
                    {
                        //SetUp Cryptographic Algorythm
                        using (RijndaelManaged AES = new RijndaelManaged())
                        {
                            //Define AES
                            AES.KeySize = 256;
                            AES.BlockSize = 128;
                            AES.Mode = CipherMode.CBC;

                            //Define AES Key
                            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(passwordBytes, _saltBytes, 1000);
                            AES.Key = key.GetBytes(AES.KeySize / 8);
                            AES.IV = key.GetBytes(AES.BlockSize / 8);

                            //SetUp CryptoStream
                            using (CryptoStream cStream = new CryptoStream(mStream, AES.CreateEncryptor(), CryptoStreamMode.Write))
                            {
                                cStream.Write(inputBytes, 0, inputBytes.Length);

                                //Close CryptoStream
                                cStream.Close();
                            }

                            //Close MemoryStream
                            mStream.Close();

                            //Transform Stream to Byte Array
                            encryptedBytes = mStream.ToArray();
                        }
                    }

                    //Return Byte Array
                    return encryptedBytes;
                }
                catch (Exception ex)
                {
                    //toDo Logging
                    throw ex;
                }
            }

            /// <summary>
            /// The AES Algorythm to Encrypt Bytes using SecureString
            /// </summary>
            /// <param name="inputBytes">Input Byte Array</param>
            /// <param name="password">Secure Password</param>
            /// <returns>Encrypted Byte Array</returns>
            internal static byte[] Encrypt(byte[] inputBytes, SecureString password)
            {
                try
                {
                    //SetUp Memory Stream
                    using (MemoryStream mStream = new MemoryStream())
                    {
                        //SetUp Cryptographic Algorythm
                        using (RijndaelManaged AES = new RijndaelManaged())
                        {
                            //Define AES
                            AES.KeySize = 256;
                            AES.BlockSize = 128;
                            AES.Mode = CipherMode.CBC;

                            //Get Key Bytes
                            byte[] keyBytes = new byte[AES.KeySize / 8];

                            //Convert Secure Password Bytes
                            IntPtr marshalledKeyBytes = Marshal.SecureStringToGlobalAllocAnsi(password);
                            Marshal.Copy(marshalledKeyBytes, keyBytes, 0, Math.Min(keyBytes.Length, password.Length));

                            //Define AES Key
                            AES.Key = keyBytes;
                            AES.IV = _saltBytes;

                            //SetUp CryptoStream
                            using (CryptoStream cStream = new CryptoStream(mStream, AES.CreateEncryptor(), CryptoStreamMode.Write))
                            {
                                cStream.Write(inputBytes, 0, inputBytes.Length);

                                //Close CryptoStream
                                cStream.Close();
                            }

                            //Close MemoryStream
                            mStream.Close();

                            //Remove Critical Data from Memory
                            Marshal.ZeroFreeGlobalAllocAnsi(marshalledKeyBytes);

                            //Return Decrypted Byte Array
                            return mStream.ToArray();
                        }
                    }
                }
                catch (Exception ex)
                {
                    //toDo Logging
                    throw ex;
                }
            }

            /// <summary>
            /// The AES Algorythm to Encrypt Stream using Password Byte Array
            /// </summary>
            /// <param name="inputStream">Input Stream</param>
            /// <param name="passwordBytes">Password Byte Array</param>
            /// <returns>Encrypted Stream</returns>
            internal static Stream Encrypt(Stream inputStream, byte[] passwordBytes)
            {
                try
                {
                    //SetUp Cryptographic Algorythm
                    using (RijndaelManaged AES = new RijndaelManaged())
                    {
                        //Define AES
                        AES.KeySize = 256;
                        AES.BlockSize = 128;
                        AES.Mode = CipherMode.CBC;

                        //Get Key Bytes
                        byte[] keyBytes = new byte[AES.KeySize / 8];

                        //Define AES Key
                        Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(passwordBytes, _saltBytes, 1000);
                        AES.Key = key.GetBytes(AES.KeySize / 8);
                        AES.IV = key.GetBytes(AES.BlockSize / 8);

                        //SetUp Cryptographic Trasformer
                        ICryptoTransform cTransform = AES.CreateEncryptor();

                        //Return CryptoStream
                        return new CryptoStream(inputStream, cTransform, CryptoStreamMode.Write);
                    }
                }
                catch (Exception ex)
                {
                    //toDo Logging
                    throw ex;
                }
            }

            /// <summary>
            /// The AES Algorythm to Encrypt Stream using SecureString
            /// </summary>
            /// <param name="inputStream">Input Stream</param>
            /// <param name="password">Secure Password</param>
            /// <returns>Encrypted Stream</returns>
            internal static Stream Encrypt(Stream inputStream, SecureString password)
            {
                try
                {
                    //SetUp Cryptographic Algorythm
                    using (RijndaelManaged AES = new RijndaelManaged())
                    {
                        //Define AES
                        AES.KeySize = 256;
                        AES.BlockSize = 128;
                        AES.Mode = CipherMode.CBC;

                        //Get Key Bytes
                        byte[] keyBytes = new byte[AES.KeySize / 8];

                        //Convert Secure Password Bytes
                        IntPtr marshalledKeyBytes = Marshal.SecureStringToGlobalAllocAnsi(password);
                        Marshal.Copy(marshalledKeyBytes, keyBytes, 0, Math.Min(keyBytes.Length, password.Length));

                        //Define AES Key
                        AES.Key = keyBytes;
                        AES.IV = _saltBytes;

                        //SetUp Cryptographic Trasformer
                        ICryptoTransform cTransform = AES.CreateEncryptor();

                        //Return CryptoStream
                        return new CryptoStream(inputStream, cTransform, CryptoStreamMode.Write);
                    }
                }
                catch (Exception ex)
                {
                    //toDo Logging
                    throw ex;
                }
            }

            /// <summary>
            /// The AES Algorythm to Decrypt Bytes using Password Byte Array
            /// </summary>
            /// <param name="inputBytes">Input Byte Array</param>
            /// <param name="passwordBytes">Password Byte Array</param>
            /// <returns>Decrypted Byte Array</returns>
            internal static byte[] Decrypt(byte[] inputBytes, byte[] passwordBytes)
            {
                try
                {
                    //SetUp Output Byte Array
                    byte[] decryptedBytes = null;

                    //SetUp Memory Stream
                    using (MemoryStream mStream = new MemoryStream())
                    {
                        //SetUp Cryptographic Algorythm
                        using (RijndaelManaged AES = new RijndaelManaged())
                        {
                            //Define AES
                            AES.KeySize = 256;
                            AES.BlockSize = 128;
                            AES.Mode = CipherMode.CBC;

                            //Define AES Key
                            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(passwordBytes, _saltBytes, 1000);
                            AES.Key = key.GetBytes(AES.KeySize / 8);
                            AES.IV = key.GetBytes(AES.BlockSize / 8);

                            //SetUp CryptoStream
                            using (CryptoStream cStream = new CryptoStream(mStream, AES.CreateDecryptor(), CryptoStreamMode.Write))
                            {
                                cStream.Write(inputBytes, 0, inputBytes.Length);

                                //Close CryptoStream
                                cStream.Close();
                            }

                            //Close MemoryStream
                            mStream.Close();

                            //Transform Stream to Byte Array
                            decryptedBytes = mStream.ToArray();
                        }
                    }

                    //Return Byte Array
                    return decryptedBytes;
                }
                catch (Exception ex)
                {
                    //toDo Logging
                    throw ex;
                }
            }

            /// <summary>
            /// The AES Algorythm to Decrypt Bytes using SecureString
            /// </summary>
            /// <param name="inputBytes">Input Byte Array</param>
            /// <param name="password">Secure Password</param>
            /// <returns>Decrypted Byte Array</returns>
            internal static byte[] Decrypt(byte[] inputBytes, SecureString password)
            {
                try
                {
                    //SetUp Memory Stream
                    using (MemoryStream mStream = new MemoryStream())
                    {
                        //SetUp Cryptographic Algorythm
                        using (RijndaelManaged AES = new RijndaelManaged())
                        {
                            //Define AES
                            AES.KeySize = 256;
                            AES.BlockSize = 128;
                            AES.Mode = CipherMode.CBC;

                            //Get Key Bytes
                            byte[] keyBytes = new byte[AES.KeySize / 8];

                            //Convert Secure Password Bytes
                            IntPtr marshalledKeyBytes = Marshal.SecureStringToGlobalAllocAnsi(password);
                            Marshal.Copy(marshalledKeyBytes, keyBytes, 0, Math.Min(keyBytes.Length, password.Length));

                            //Define AES Key
                            AES.Key = keyBytes;
                            AES.IV = _saltBytes;

                            //SetUp CryptoStream
                            using (CryptoStream cStream = new CryptoStream(mStream, AES.CreateDecryptor(), CryptoStreamMode.Write))
                            {
                                cStream.Write(inputBytes, 0, inputBytes.Length);

                                //Close CryptoStream
                                cStream.Close();
                            }

                            //Close MemoryStream
                            mStream.Close();

                            //Remove Critical Data from Memory
                            Marshal.ZeroFreeGlobalAllocAnsi(marshalledKeyBytes);

                            //Return Decrypted Byte Array
                            return mStream.ToArray();
                        }
                    }
                }
                catch (Exception ex)
                {
                    //toDo Logging
                    throw ex;
                }
            }

            /// <summary>
            /// The AES Algorythm to Decrypt Stream using Password Byte Array
            /// </summary>
            /// <param name="inputStream">Input Stream</param>
            /// <param name="passwordBytes">Password Byte Array</param>
            /// <returns>Decrypted Stream</returns>
            internal static Stream Decrypt(Stream inputStream, byte[] passwordBytes)
            {
                try
                {
                    //SetUp Cryptographic Algorythm
                    using (RijndaelManaged AES = new RijndaelManaged())
                    {
                        //Define AES
                        AES.KeySize = 256;
                        AES.BlockSize = 128;
                        AES.Mode = CipherMode.CBC;

                        //Get Key Bytes
                        byte[] keyBytes = new byte[AES.KeySize / 8];

                        //Define AES Key
                        Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(passwordBytes, _saltBytes, 1000);
                        AES.Key = key.GetBytes(AES.KeySize / 8);
                        AES.IV = key.GetBytes(AES.BlockSize / 8);

                        //SetUp Cryptographic Trasformer
                        ICryptoTransform cTransform = AES.CreateDecryptor();

                        //Return CryptoStream
                        return new CryptoStream(inputStream, cTransform, CryptoStreamMode.Read);
                    }
                }
                catch (Exception ex)
                {
                    //toDo Logging
                    throw ex;
                }
            }

            /// <summary>
            /// The AES Algorythm to Decrypt Stream using SecureString
            /// </summary>
            /// <param name="inputStream">Input Stream</param>
            /// <param name="password">Secure Password</param>
            /// <returns>Decrypted Stream</returns>
            internal static Stream Decrypt(Stream inputStream, SecureString password)
            {
                try
                {
                    //SetUp Cryptographic Algorythm
                    using (RijndaelManaged AES = new RijndaelManaged())
                    {
                        //Define AES
                        AES.KeySize = 256;
                        AES.BlockSize = 128;
                        AES.Mode = CipherMode.CBC;

                        //Get Key Bytes
                        byte[] keyBytes = new byte[AES.KeySize / 8];

                        //Convert Secure Password Bytes
                        IntPtr marshalledKeyBytes = Marshal.SecureStringToGlobalAllocAnsi(password);
                        Marshal.Copy(marshalledKeyBytes, keyBytes, 0, Math.Min(keyBytes.Length, password.Length));

                        //Define AES Key
                        AES.Key = keyBytes;
                        AES.IV = _saltBytes;

                        //SetUp Cryptographic Trasformer
                        ICryptoTransform cTransform = AES.CreateDecryptor();

                        //Return CryptoStream
                        return new CryptoStream(inputStream, cTransform, CryptoStreamMode.Read);
                    }
                }
                catch (Exception ex)
                {
                    //toDo Logging
                    throw ex;
                }
            }
        }
    }

    /// <summary>
    /// Available Algorythms
    /// </summary>
    public enum Algorythms
    {
        /// <summary>
        /// The AES Algorythm with 256 Bit Encryption
        /// </summary>
        AES256
    }
}