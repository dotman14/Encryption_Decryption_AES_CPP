/*
File:       CryptAES.cpp
Written by: Oyedotun Oyesanmi
Date:       11/20/2015
Desc:       Implementation file for encryption and decryption program.
*/

#include <iostream>
#include <fstream>
#include <string>
#include <C:\path\to\Cryptocpp\osrng.h>
#include <C:\path\to\Cryptocpp\cryptlib.h>
#include <C:\path\to\Cryptocpp\hex.h>
#include <C:\path\to\Cryptocpp\filters.h>
#include <C:\path\to\Cryptocpp\files.h>
#include <C:\path\to\Cryptocpp\aes.h>
#include <C:\path\to\Cryptocpp\modes.h>
#include <C:\path\to\Cryptocpp\sha.h>
#include "CryptAES.h"
using namespace std;

void DisplayMenu()
{
	cout << "****************************************\n";
	cout << "****** Encypt and Decrypt Program ******\n";
	cout << "****** Press 1 to Encrypt **************\n";
	cout << "****** Press 2 to Decrypt **************\n";
	cout << "****** Press 3 to exit the program *****\n";
	cout << "****************************************\n";
}


void Encrypt(string fileName, string key)
{
	ifstream openPlainTextFile(fileName + ".txt");

	if (!openPlainTextFile.is_open())
		cout << "The input file you want to encrypt does not exist\n\n";
	else
	{
		try
		{
			//Read all data from file and store all inside plainText
			string plainText((istreambuf_iterator<char>(openPlainTextFile)), (istreambuf_iterator<char>()));

			string encoded, decoded, cipher;

			//This is used to instantiate an Encryption object of AES using the ECB_Mode of operation.
			CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption encryption;
			encryption.SetKey((byte*)key.c_str(), 32);

			//Actual encryption happens here, cipher text is scrambled at this point.
			CryptoPP::StringSource(plainText, true, new CryptoPP::StreamTransformationFilter(encryption, new CryptoPP::StringSink(cipher)));

			/*
			A step further in our encryption. Cipher text is Encoded using HexEncoder.
			NOTE_TO_SELF: Tried to work with the scrambled, wierd looking cipher text but couldn't decrypt it.
			So Hexing it was a library sugested and viable option.
			*/
			CryptoPP::StringSource(cipher, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded)));

			openPlainTextFile.close();

			//Write encrypted data to fileName and append .Crypt filename at the end.
			WriteToFile(fileName + ".Crypt", encoded);

			//Write hashed data to fileName and append .Hash filename at the end.
			WriteToFile(fileName + ".Hash", CreateHash(plainText));
		}
		catch (CryptoPP::Exception const& e)
		{
			/*cout << e.what() << endl; 
			Actual error message from CryptoPP, 
			but we do not want to be a loosed mouth system
			*/
			cout << "Something went wrong with the file encrption. Please try again\n\n";
			return;
		}
	}
}

void Decrypt(string fileName, string key)
{
	ifstream openCipherTextFile(fileName + ".Crypt");

	if (!openCipherTextFile.is_open())
		cout << "The input file you want to decrypt does not exist\n\n";
	else
	{
		try
		{
			string decoded, plainText;

			//Read all data from file and store all inside plainText
			string cipherText((istreambuf_iterator<char>(openCipherTextFile)), (istreambuf_iterator<char>()));

			//This is used to instantiate an Decryption object of AES using the ECB_Mode of operation.
			CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption decryption;
			decryption.SetKey((byte*)key.c_str(), 32);

			//First we need to Decode the encoded cipher using the HexDecoder function of CryptoPP
			CryptoPP::StringSource(cipherText, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded)));

			//Actual deryption happens here, decoded text is converted to plaintext at this point.
			CryptoPP::StringSource(decoded, true, new CryptoPP::StreamTransformationFilter(decryption, new CryptoPP::StringSink(plainText)));

			openCipherTextFile.close();

			//Write plainText to a file
			WriteToFile("C:\\Users\\dotun\\Desktop\\" + fileName + ".txt", plainText);
		}
		catch (CryptoPP::Exception const& e)
		{
			/*cout << e.what() << endl; 
			Actual error message from CryptoPP, 
			but we do not want to be a loosed mouth system
			*/
			cout << "Something went wrong with the file encrption. Please try again\n\n";
			return;
		}

		//We need to grab all the data from the hash file we created when we encrypted the plaintext.
		ifstream hashFileOpen(fileName + ".hash");
		string hashString((istreambuf_iterator<char>(hashFileOpen)), (istreambuf_iterator<char>()));
		hashFileOpen.close();

		//We hash the content of the plainText we just decrypted
		ifstream fileOpen(fileName + "1.txt");
		string hashFileData((istreambuf_iterator<char>(fileOpen)), (istreambuf_iterator<char>()));
		fileOpen.close();

		//Compare both hashes from above to determine if message intgrity has been violated. If so CALL 911.
		if (hashString.compare(CreateHash(hashFileData)) == 0)
			cout << "Integrity is Intact\n\n";
		else
			cout << "Integrity has been compromised call 911\n\n";
	}
}

string CreateHash(string fileData)
{
	//Instantiate our hash function of SHA512.
	CryptoPP::SHA512 hash;
	CryptoPP::HexEncoder encoder;
	string hashValue;

	byte hashSize[CryptoPP::SHA512::DIGESTSIZE];
	hash.CalculateDigest(hashSize, (byte*)fileData.c_str(), fileData.length());
	encoder.Attach(new CryptoPP::StringSink(hashValue));
	encoder.Put(hashSize, sizeof(hashSize));
	encoder.MessageEnd();

	return hashValue;
}

void WriteToFile(string fileName, string data)
{
	ofstream dataFile(fileName);
	dataFile << data;
	dataFile.close();
}
