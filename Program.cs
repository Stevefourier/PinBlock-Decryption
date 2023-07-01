using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


namespace ForEncAndDec
{
    class Program
    {
        static void Main(string[] args)
        {

            byte[] iv = new byte[8];
            byte[] comp4 = ConvertHexStringToBytes("FA6FAEAA49DEB275519BD1418233D6B3");
            byte[] Component2 = ConvertHexStringToBytes("B4C5FA4CF1EE8E06B42E7E475DBF1272");
           
            byte[] component3 = ConvertHexStringToBytes("0DF774D1E3CBEA50BD3CF29D3956770C");
          
            byte[] clearZMK = xorIt(comp4, Component2, component3);

            Key ZMKkey = new Key(clearZMK, 0, 0);

            //byte[] finalKey=   xorIt(comp4, Component2, component3);
            Console.WriteLine("ZMK = {0}", BitConverter.ToString(clearZMK).Replace("-",""));
            Console.WriteLine("ZMK KCV = {0}",BitConverter.ToString( TripleDESECB(ZMKkey,iv, CypherMode.MODE_ENCRYPT)).Replace("-","").Substring(0,6));

            string kek = "48F4B0CEDB1635B7CAF24951F35F5CF6";
            byte[] KEKByte = ConvertHexStringToBytes(kek);
         
            byte[] clearKekKey = TripleDESECB(ZMKkey, KEKByte, CypherMode.MODE_DECRYPT);


            Key kekkey = new Key(clearKekKey, 0, 0);
            Console.WriteLine("KEK KCV = {0}", BitConverter.ToString( TripleDESECB(kekkey, iv, CypherMode.MODE_ENCRYPT)));
            Console.WriteLine("KEK = {0}", BitConverter.ToString(clearKekKey).Replace("-", ""));


            byte[] UDKAC = ConvertHexStringToBytes("2a475d35146a6b566293d6bbf6aef2b0");
            byte[] UDKENC = ConvertHexStringToBytes("eec58bd70dfa9e6f7ea25a583a0faa1c");
            byte[] UDKMAC = ConvertHexStringToBytes("f71967ad3bdc5ea8914982f8307389dc");
            byte[] UDKIDN = ConvertHexStringToBytes("2a475d35146a6b566293d6bbf6aef2b0");
            byte[] pinBlock = ConvertHexStringToBytes("73B4AA123F8D44B8");           
            
            byte[] clearUDKAC = TripleDESECB(kekkey, UDKAC, CypherMode.MODE_DECRYPT);
            Key clearUDKAC2 = new Key(clearUDKAC, 0, 0);
            Console.WriteLine("UDKAC KCV = {0}", BitConverter.ToString(TripleDESECB(clearUDKAC2, iv, CypherMode.MODE_ENCRYPT)).Replace("_", ""));
            Console.WriteLine("clearUDKAC = {0}", BitConverter.ToString(clearUDKAC).Replace("-", ""));

            byte[] clearUDKENC = TripleDESECB(kekkey, UDKENC, CypherMode.MODE_DECRYPT);
            Key clearUDKENC2 = new Key(clearUDKENC, 0, 0);
            Console.WriteLine("UDKENC KCV = {0}", BitConverter.ToString(TripleDESECB(clearUDKENC2, iv, CypherMode.MODE_ENCRYPT)).Replace("_", ""));
            Console.WriteLine("clearUDKENC = {0}", BitConverter.ToString(clearUDKENC).Replace("-", ""));

            byte[] clearUDKMAC = TripleDESECB(kekkey, UDKMAC, CypherMode.MODE_DECRYPT);
            Key clearUDKMAC2 = new Key(clearUDKMAC, 0, 0);
            Console.WriteLine("UDKMAC KCV = {0}", BitConverter.ToString(TripleDESECB(clearUDKMAC2, iv, CypherMode.MODE_ENCRYPT)));
            Console.WriteLine("clearUDKMAC = {0}", BitConverter.ToString(clearUDKMAC).Replace("-", ""));

            byte[] clearUDKIDN = TripleDESECB(kekkey, UDKIDN, CypherMode.MODE_DECRYPT);
            Key clearUDKIDN2 = new Key(clearUDKIDN, 0, 0);
            Console.WriteLine("UDKIDN KCV = {0}", BitConverter.ToString(TripleDESECB(clearUDKIDN2, iv, CypherMode.MODE_ENCRYPT)));
            Console.WriteLine("clearUDKIDN = {0}", BitConverter.ToString(clearUDKIDN).Replace("-", ""));

            byte[] clearpinBlock = TripleDESECB(kekkey, pinBlock, CypherMode.MODE_DECRYPT);
            Key clearpinBlock2 = new Key(clearpinBlock, 0, 0);
            //Console.WriteLine("UDKIDN KCV = {0}", BitConverter.ToString(TripleDESECB(clearUDKIDN2, iv, CypherMode.MODE_ENCRYPT)));
            Console.WriteLine("clearpinBlock = {0}", BitConverter.ToString(clearpinBlock).Replace("-", ""));

            Console.WriteLine(BitConverter.ToString(clearZMK, 0).Replace("-",""));
            Console.ReadKey();

        }

       
        public static byte[] xorIt(byte[] key, byte[] input) { 

            StringBuilder sb = new StringBuilder();
            byte[] result = new byte[16];
            //byte[] Comp1 = Encoding.ASCII.GetBytes(key);
            //byte[] Comp2 = Encoding.ASCII.GetBytes(input);


            for (int i = 0; i <key .Length; i++)
            {
               result[i] = ((byte)( key[i] ^ input[i]));
            }
            

            return result;
        }
        public static byte[] xorIt(params object[] values)
        {
            int length = values.Count();
            if (length < 1)
                throw new Exception("Values supplied must be greater than 1");
            
            List<byte[]> args = new List<byte[]>();
          
            for (int i = 0; i < values.Count(); i++)
            {
                args.Add( (byte[])values[i]);
            }

            int ln = args[1].Length;
            byte[] result = new byte[ln];
            //byte[]result2 = new byte[ln];
            foreach (byte[] item in args)
            {
                for (int i = 0; i < item.Length; i++)
                {
                    result[i] ^= item[i];
                }
                
            }

            
            return result;
        }

        public static string Decrypt(string encryptedText, byte[] key)
        {
            byte[] VIKey = new byte[8];
            byte[] cipherTextBytes = ConvertHexStringToBytes(encryptedText);
            //byte[] keyBytes = new Rfc2898DeriveBytes(PasswordHash, Encoding.ASCII.GetBytes(SaltKey)).GetBytes(256 / 8);
            var symmetricKey = new RijndaelManaged() { Mode = CipherMode.ECB, Padding = PaddingMode.None };

            var decryptor = symmetricKey.CreateDecryptor(key, VIKey);
            var memoryStream = new MemoryStream(cipherTextBytes);
            var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];

            int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
            memoryStream.Close();
            cryptoStream.Close();
            return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
        }
        public static string Encrypt(byte[] plainText, byte[] key)
        {
            byte[] plainTextBytes = plainText;
            byte[] VIKey = new byte[8];
            byte[] keyBytes = key;
            var symmetricKey = new RijndaelManaged() { Mode = CipherMode.ECB };
            var encryptor = symmetricKey.CreateEncryptor(keyBytes, VIKey);

            byte[] cipherTextBytes;

            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                    cryptoStream.FlushFinalBlock();
                    cipherTextBytes = memoryStream.ToArray();
                    cryptoStream.Close();
                }
                memoryStream.Close();
            }
            return BitConverter.ToString(cipherTextBytes).Replace("-","");
        }
        public static byte[] ConvertHexStringToBytes(string str)
        {
            str = str.Replace(" ", "");
            byte[] buffer = new byte[str.Length / 2];
            for (int i = 0; i < str.Length; i += 2)
                buffer[i / 2] = (byte)Convert.ToByte(str.Substring(i, 2), 16);
            return buffer;
        }


        static byte[] Encrypt(string plainText, byte[] Key, byte[] IV)
        {
            byte[] encrypted;
            // Create a new TripleDESCryptoServiceProvider.  
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                // Create encryptor  
                ICryptoTransform encryptor = tdes.CreateEncryptor(Key, IV);
                // Create MemoryStream  
                using (MemoryStream ms = new MemoryStream())
                {
                    // Create crypto stream using the CryptoStream class. This class is the key to encryption  
                    // and encrypts and decrypts data from any given stream. In this case, we will pass a memory stream  
                    // to encrypt  
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        // Create StreamWriter and write data to a stream  
                        using (StreamWriter sw = new StreamWriter(cs))
                            sw.Write(plainText);
                        encrypted = ms.ToArray();
                    }
                }
            }
            // Return encrypted data  
            return encrypted;
        }
        static string Decrypt(byte[] cipherText, byte[] Key, byte[] IV)
        {
            string plaintext = null;
            // Create TripleDESCryptoServiceProvider  
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                // Create a decryptor  
                ICryptoTransform decryptor = tdes.CreateDecryptor(Key, IV);
                // Create the streams used for decryption.  
                using (MemoryStream ms = new MemoryStream(cipherText))
                {
                    // Create crypto stream  
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        // Read crypto stream  
                        using (StreamReader reader = new StreamReader(cs))
                            plaintext = reader.ReadToEnd();
                    }
                }
            }
            return plaintext;
        }

        public static byte[] TripleDESECB(Key key, byte[] data, CypherMode operationMode)
        {
            byte[] result = null;
            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            if (operationMode == CypherMode.MODE_DECRYPT)
            {
                tdes.Mode = CipherMode.ECB;
                tdes.Padding = PaddingMode.None;
                ICryptoTransform decryptor = tdes.CreateDecryptor(key.Value, null);
                result = decryptor.TransformFinalBlock(data, 0, data.Length);
            }
            else if (operationMode == CypherMode.MODE_ENCRYPT)
            {
                tdes.Mode = CipherMode.ECB;
                tdes.Padding = PaddingMode.None;
                ICryptoTransform encryptor = tdes.CreateEncryptor(key.Value, null);
                result = encryptor.TransformFinalBlock(data, 0, data.Length);
            }
            return result;
        }
        public static byte[] TripleDESCBC(Key key, byte[] data, CypherMode operationMode, CipherMode ciphermode)
        {
            byte[] result = null;
            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            if (operationMode == CypherMode.MODE_DECRYPT)
            {
                tdes.Mode = CipherMode.CBC;
                tdes.Padding = PaddingMode.None;
                ICryptoTransform decryptor = tdes.CreateDecryptor(key.Value, null);
                result = decryptor.TransformFinalBlock(data, 0, data.Length);
            }
            else if (operationMode == CypherMode.MODE_ENCRYPT)
            {
                tdes.Mode = CipherMode.CBC;
                tdes.Padding = PaddingMode.None;
                ICryptoTransform encryptor = tdes.CreateEncryptor(key.Value, null);
                result = encryptor.TransformFinalBlock(data, 0, data.Length);
            }
            return result;
        }

        public enum CypherMode : int
        {
            /// <summary>
            /// Operate at encryption mode
            /// </summary>
            MODE_ENCRYPT = 0x00,

            /// <summary>
            /// Operate at decryption mode
            /// </summary>
            MODE_DECRYPT = 0x01
        }
    }

    public class Key
    {
        #region Constant Fields

        public const int KEY_TYPE_ENC = 0x01;
        public const int KEY_TYPE_MAC = 0x02;
        public const int KEY_TYPE_KEK = 0x03;
        public const int KEY_TYPE_RMAC = 0x04;

        #endregion

        #region Private Fields

        private byte[] mValue;
        private readonly int mKeyId;
        private readonly int mKeyVersion;

        #endregion

        #region Public Properties

        /// <summary>
        /// Key value
        /// </summary>
        public byte[] Value
        {
            get { return mValue; }
        }

        /// <summary>
        /// Key version
        /// </summary>
        public int KeyVersion
        {
            get { return mKeyVersion; }
        }

        /// <summary>
        /// Key Id
        /// </summary>
        public int KeyId
        {
            get { return mKeyId; }
        }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs a key from byte array
        /// </summary>
        /// <param name="value">Key value</param>
        /// <param name="keyId">Key Id</param>
        /// <param name="keyVersion">Key Version</param>
        public Key(byte[] value, int keyId = 0, int keyVersion = 0)
        {
            this.mValue = value;
            mKeyId = keyId;
            mKeyVersion = keyVersion;
        }

        /// <summary>
        /// Constructs a key from hex string represntation
        /// </summary>
        /// <param name="value">Key value</param>
        /// <param name="keyId">Key Id</param>
        /// <param name="keyVersion">Key Version</param>
        public Key(string value, int keyId = 0, int keyVersion = 0)
        {
            string hex = value;
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);

            this.mValue = bytes;
            mKeyId = keyId;
            mKeyVersion = keyVersion;
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Builds 3DES key from this key value
        /// </summary>
        /// <returns></returns>
        public byte[] BuildTripleDesKey()
        {
            byte[] tdesKey = new byte[24];
            System.Array.Copy(mValue, 0, tdesKey, 0, 16);
            System.Array.Copy(mValue, 0, tdesKey, 16, 8);
            return tdesKey;
        }

        /// <summary>
        /// Builds DES key from this key value
        /// </summary>
        /// <returns></returns>
        public byte[] BuildDesKey()
        {
            byte[] desKey = new byte[8];
            System.Array.Copy(mValue, 0, desKey, 0, 8);
            return desKey;
        }

        #endregion
    }
}

