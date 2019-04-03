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
        /// The AES Algorythm with 128 Bit Encryption
        /// </summary>
        internal static class AES128
        {
            /// <summary>
            /// Default Salt used for Encryption
            /// </summary>
            private static byte[] _saltBytes = new byte[] { 6, 4, 4, 0, 6, 0, 6, 7, 1, 1, 3, 9, 7, 0, 8, 8 };

            /// <summary>
            /// The BitSize for Encryption
            /// </summary>
            private static int _bitSize = 128;

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
                    //SetUp Memory Stream
                    using (MemoryStream mStream = new MemoryStream())
                    {
                        //SetUp Cryptographic Algorythm
                        using (RijndaelManaged AES = new RijndaelManaged())
                        {
                            //Define AES
                            AES.KeySize = _bitSize;
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

                            //Transform and return Stream to Byte Array
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
                            AES.KeySize = _bitSize;
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
                        AES.KeySize = _bitSize;
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
                        AES.KeySize = _bitSize;
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
                    //SetUp Memory Stream
                    using (MemoryStream mStream = new MemoryStream())
                    {
                        //SetUp Cryptographic Algorythm
                        using (RijndaelManaged AES = new RijndaelManaged())
                        {
                            //Define AES
                            AES.KeySize = _bitSize;
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

                            //Transform and return Stream to Byte Array
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
                            AES.KeySize = _bitSize;
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
                        AES.KeySize = _bitSize;
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
                        AES.KeySize = _bitSize;
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

        /// <summary>
        /// The AES Algorythm with 160 Bit Encryption
        /// </summary>
        internal static class AES160
        {
            /// <summary>
            /// Default Salt used for Encryption
            /// </summary>
            private static byte[] _saltBytes = new byte[] { 6, 4, 4, 0, 6, 0, 6, 7, 1, 1, 3, 9, 7, 0, 8, 8 };

            /// <summary>
            /// The BitSize for Encryption
            /// </summary>
            private static int _bitSize = 160;

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
                    //SetUp Memory Stream
                    using (MemoryStream mStream = new MemoryStream())
                    {
                        //SetUp Cryptographic Algorythm
                        using (RijndaelManaged AES = new RijndaelManaged())
                        {
                            //Define AES
                            AES.KeySize = _bitSize;
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

                            //Transform and return Stream to Byte Array
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
                            AES.KeySize = _bitSize;
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
                        AES.KeySize = _bitSize;
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
                        AES.KeySize = _bitSize;
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
                    //SetUp Memory Stream
                    using (MemoryStream mStream = new MemoryStream())
                    {
                        //SetUp Cryptographic Algorythm
                        using (RijndaelManaged AES = new RijndaelManaged())
                        {
                            //Define AES
                            AES.KeySize = _bitSize;
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

                            //Transform and return Stream to Byte Array
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
                            AES.KeySize = _bitSize;
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
                        AES.KeySize = _bitSize;
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
                        AES.KeySize = _bitSize;
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

        /// <summary>
        /// The AES Algorythm with 192 Bit Encryption
        /// </summary>
        internal static class AES192
        {
            /// <summary>
            /// Default Salt used for Encryption
            /// </summary>
            private static byte[] _saltBytes = new byte[] { 6, 4, 4, 0, 6, 0, 6, 7, 1, 1, 3, 9, 7, 0, 8, 8 };

            /// <summary>
            /// The BitSize for Encryption
            /// </summary>
            private static int _bitSize = 192;

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
                    //SetUp Memory Stream
                    using (MemoryStream mStream = new MemoryStream())
                    {
                        //SetUp Cryptographic Algorythm
                        using (RijndaelManaged AES = new RijndaelManaged())
                        {
                            //Define AES
                            AES.KeySize = _bitSize;
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

                            //Transform and return Stream to Byte Array
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
                            AES.KeySize = _bitSize;
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
                        AES.KeySize = _bitSize;
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
                        AES.KeySize = _bitSize;
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
                    //SetUp Memory Stream
                    using (MemoryStream mStream = new MemoryStream())
                    {
                        //SetUp Cryptographic Algorythm
                        using (RijndaelManaged AES = new RijndaelManaged())
                        {
                            //Define AES
                            AES.KeySize = _bitSize;
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

                            //Transform and return Stream to Byte Array
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
                            AES.KeySize = _bitSize;
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
                        AES.KeySize = _bitSize;
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
                        AES.KeySize = _bitSize;
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

        /// <summary>
        /// The AES Algorythm with 224 Bit Encryption
        /// </summary>
        internal static class AES224
        {
            /// <summary>
            /// Default Salt used for Encryption
            /// </summary>
            private static byte[] _saltBytes = new byte[] { 6, 4, 4, 0, 6, 0, 6, 7, 1, 1, 3, 9, 7, 0, 8, 8 };

            /// <summary>
            /// The BitSize for Encryption
            /// </summary>
            private static int _bitSize = 224;

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
                    //SetUp Memory Stream
                    using (MemoryStream mStream = new MemoryStream())
                    {
                        //SetUp Cryptographic Algorythm
                        using (RijndaelManaged AES = new RijndaelManaged())
                        {
                            //Define AES
                            AES.KeySize = _bitSize;
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

                            //Transform and return Stream to Byte Array
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
                            AES.KeySize = _bitSize;
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
                        AES.KeySize = _bitSize;
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
                        AES.KeySize = _bitSize;
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
                    //SetUp Memory Stream
                    using (MemoryStream mStream = new MemoryStream())
                    {
                        //SetUp Cryptographic Algorythm
                        using (RijndaelManaged AES = new RijndaelManaged())
                        {
                            //Define AES
                            AES.KeySize = _bitSize;
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

                            //Transform and return Stream to Byte Array
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
                            AES.KeySize = _bitSize;
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
                        AES.KeySize = _bitSize;
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
                        AES.KeySize = _bitSize;
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

        /// <summary>
        /// The AES Algorythm with 256 Bit Encryption
        /// </summary>
        internal static class AES265
        {
            /// <summary>
            /// Default Salt used for Encryption
            /// </summary>
            private static byte[] _saltBytes = new byte[] { 6, 4, 4, 0, 6, 0, 6, 7, 1, 1, 3, 9, 7, 0, 8, 8 };

            /// <summary>
            /// The BitSize for Encryption
            /// </summary>
            private static int _bitSize = 256;

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
                    //SetUp Memory Stream
                    using (MemoryStream mStream = new MemoryStream())
                    {
                        //SetUp Cryptographic Algorythm
                        using (RijndaelManaged AES = new RijndaelManaged())
                        {
                            //Define AES
                            AES.KeySize = _bitSize;
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

                            //Transform and return Stream to Byte Array
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
                            AES.KeySize = _bitSize;
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
                        AES.KeySize = _bitSize;
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
                        AES.KeySize = _bitSize;
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
                    //SetUp Memory Stream
                    using (MemoryStream mStream = new MemoryStream())
                    {
                        //SetUp Cryptographic Algorythm
                        using (RijndaelManaged AES = new RijndaelManaged())
                        {
                            //Define AES
                            AES.KeySize = _bitSize;
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

                            //Transform and return Stream to Byte Array
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
                            AES.KeySize = _bitSize;
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
                        AES.KeySize = _bitSize;
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
                        AES.KeySize = _bitSize;
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

        /// <summary>
        /// The RSA Algorythm with 2048 Bit Encryption
        /// </summary>
        internal static class RSA2048
        {
            /// <summary>
            /// The BitSize for Encryption
            /// </summary>
            private static int _bitSize = 2048;

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
                    //SetUp Cryptographic Algorythm
                    using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(_bitSize))
                    {
                    }

                    //Return Byte Array
                    return null;
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
                    //SetUp Cryptographic Algorythm
                    using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(_bitSize))
                    {
                    }

                    //Return Byte Array
                    return null;
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
                    using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(_bitSize))
                    {
                    }

                    //Return Byte Array
                    return null;
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
                    using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(_bitSize))
                    {
                    }

                    //Return Byte Array
                    return null;
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
                    //SetUp Cryptographic Algorythm
                    using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(_bitSize))
                    {
                    }

                    //Return Byte Array
                    return null;
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
                    //SetUp Cryptographic Algorythm
                    using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(_bitSize))
                    {
                    }

                    //Return Byte Array
                    return null;
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
                    using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(_bitSize))
                    {
                    }

                    //Return Byte Array
                    return null;
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
                    using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(_bitSize))
                    {
                    }

                    //Return Byte Array
                    return null;
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
        /// The AES Algorythm with 128 Bit Encryption
        /// </summary>
        AES128,

        /// <summary>
        /// The AES Algorythm with 160 Bit Encryption
        /// </summary>
        AES160,

        /// <summary>
        /// The AES Algorythm with 192 Bit Encryption
        /// </summary>
        AES192,

        /// <summary>
        /// The AES Algorythm with 224 Bit Encryption
        /// </summary>
        AES224,

        /// <summary>
        /// The AES Algorythm with 256 Bit Encryption
        /// </summary>
        AES256,

        /// <summary>
        /// The RSA Algorythm with 2048 Bit Encryption
        /// </summary>
        RSA2048
    }
}