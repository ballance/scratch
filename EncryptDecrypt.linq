<Query Kind="Program">
  <Namespace>System</Namespace>
  <Namespace>System.Security.Cryptography</Namespace>
  <Namespace>System.Text</Namespace>
</Query>

class RSACSPSample
{

	static void Main()
	{
		try
		{
		
			//Create a UnicodeEncoder to convert between byte array and string.
			UnicodeEncoding ByteConverter = new UnicodeEncoding();

			//Create byte arrays to hold original, encrypted, and decrypted data.
			byte[] dataToEncrypt = ByteConverter.GetBytes("The quick brown fox jumps over the lazy dog.");
			byte[] encryptedData;
			byte[] decryptedData;

			//Create a new instance of RSACryptoServiceProvider to generate
			//public and private key data.
			using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(2048))
			{

				//Pass the data to ENCRYPT, the public key information 
				//(using RSACryptoServiceProvider.ExportParameters(false),
				//and a boolean flag specifying no OAEP padding.
				encryptedData = RSAEncrypt(dataToEncrypt, RSA.ExportParameters(false), false);

				Console.WriteLine("Encrypted data: {0}", ByteConverter.GetString(encryptedData));
				//Pass the data to DECRYPT, the private key information 
				//(using RSACryptoServiceProvider.ExportParameters(true),
				//and a boolean flag specifying no OAEP padding.
				decryptedData = RSADecrypt(encryptedData, RSA.ExportParameters(true), false);

				//Display the decrypted plaintext to the console. 
				Console.WriteLine(RSA.KeyExchangeAlgorithm);
				Console.WriteLine("mod:{0} - P:{1} - Q:{2} - ^:{3}", 
					ByteConverter.GetString(RSA.ExportParameters(true).Modulus), 
					ByteConverter.GetString(RSA.ExportParameters(true).P),
					ByteConverter.GetString(RSA.ExportParameters(true).Q), 
					ByteConverter.GetString(RSA.ExportParameters(true).Exponent));
				Console.WriteLine("Decrypted plaintext: {0}", ByteConverter.GetString(decryptedData));
			}
		}
		catch (ArgumentNullException)
		{
			//Catch this exception in case the encryption did
			//not succeed.
			Console.WriteLine("Encryption failed.");

		}
	}

	static public byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
	{
		try
		{
			byte[] encryptedData;
			//Create a new instance of RSACryptoServiceProvider.
			using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
			{

				//Import the RSA Key information. This only needs
				//toinclude the public key information.
				RSA.ImportParameters(RSAKeyInfo);

				//Encrypt the passed byte array and specify OAEP padding.  
				//OAEP padding is only available on Microsoft Windows XP or
				//later.  
				encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
			}
			return encryptedData;
		}
		//Catch and display a CryptographicException  
		//to the console.
		catch (CryptographicException e)
		{
			Console.WriteLine(e.Message);

			return null;
		}

	}

	static public byte[] RSADecrypt(byte[] DataToDecrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
	{
		try
		{
			byte[] decryptedData;
			//Create a new instance of RSACryptoServiceProvider.
			using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
			{
				//Import the RSA Key information. This needs
				//to include the private key information.
				RSA.ImportParameters(RSAKeyInfo);

				//Decrypt the passed byte array and specify OAEP padding.  
				//OAEP padding is only available on Microsoft Windows XP or
				//later.  
				decryptedData = RSA.Decrypt(DataToDecrypt, DoOAEPPadding);
			}
			return decryptedData;
		}
		//Catch and display a CryptographicException  
		//to the console.
		catch (CryptographicException e)
		{
			Console.WriteLine(e.ToString());

			return null;
		}

	}
}