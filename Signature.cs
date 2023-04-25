using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace blockChain_LR1
{
    class SignVerify
    {
        // Create a UnicodeEncoder to convert between byte array and string.
        static ASCIIEncoding ByteConverter = new ASCIIEncoding();

        // Create byte arrays to hold original, encrypted, and decrypted data.
        static byte[] originalData { get; set; }
        static byte[] signedData { get; set; }

        // Create a new instance of the RSACryptoServiceProvider class
        // and automatically create a new key-pair.
        static RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

        // Export the key information to an RSAParameters object.
        // You must pass true to export the private key for signing.
        // However, you do not need to export the private key
        // for verification.
        static RSAParameters Key = RSAalg.ExportParameters(true);

        public static byte[] HashAndSignBytes(byte[] DataToSign, RSAParameters Key)
        {
            try
            {
                RSAalg.ImportParameters(Key);

                // Hash and sign the data. Pass a new instance of SHA256
                // to specify the hashing algorithm.
                return RSAalg.SignData(DataToSign, SHA256.Create());
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null;
            }
        }

        public static bool VerifySignedHash(byte[] DataToVerify, byte[] SignedData, RSAParameters Key)
        {
            try
            { 
                RSAalg.ImportParameters(Key);

                // Verify the data using the signature.  Pass a new instance of SHA256
                // to specify the hashing algorithm.
                return RSAalg.VerifyData(DataToVerify, SHA256.Create(), SignedData);
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return false;
            }
        }

        public static string RSASign(string dataString)
        {
            try
            {
                // Create byte arrays to hold original, encrypted, and decrypted data.
                originalData = ByteConverter.GetBytes(dataString);

                // Hash and sign the data.
                signedData = HashAndSignBytes(originalData, Key);

                return Convert.ToBase64String(signedData);
            }
            catch (ArgumentNullException)
            {
                return "Ошибка, не удалось создать подпись";
            }
        }

        public static string RSAVerify()
        {
            // Verify the data and display the result to the
            // console.
            if (VerifySignedHash(originalData, signedData, Key))
            {
                return "Подпись прошла проверку!";
            }
            else
            {
                return "Подпись не прошла проверку!";
            }
        }
    }
}
