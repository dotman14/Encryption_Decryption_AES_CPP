#include <iostream>
#include <fstream>
#include <string>
#include <C:\Users\dotun\Documents\Cryptocpp\osrng.h>
#include <C:\Users\dotun\Documents\Cryptocpp\cryptlib.h>
#include <C:\Users\dotun\Documents\Cryptocpp\hex.h>
#include <C:\Users\dotun\Documents\Cryptocpp\filters.h>
#include <C:\Users\dotun\Documents\Cryptocpp\aes.h>
#include <C:\Users\dotun\Documents\Cryptocpp\modes.h>
#include <C:\Users\dotun\Documents\Cryptocpp\sha.h>
using namespace std;
using CryptoPP::SHA512;
using CryptoPP::Exception;
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;
using CryptoPP::StringSink;
using CryptoPP::StreamTransformation;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AES;
using CryptoPP::ECB_Mode;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::StringSource;


void DisplayMenu();
void Encrypt(string fileName, string key);
void Decrypt(string fileName, string key);
string CreateHash(string fileName, string fileData);

int main()
{
	bool exit = false;

	string filename, key;

	while (exit == false)
	{
		int response;

		DisplayMenu();

		cout << "Your selection" << "  ";
		cin >> response;

		switch (response)
		{
			case 1:
				cout << "Enter name of file you want to encrypt : ";
				cin >> filename;

				cout << "Enter your 16 digit alphanumeric key to encrypt : ";
				cin >> key;

				cout << endl;

				Encrypt(filename, key);

				break;

			case 2:
				cout << "Enter name of file you want to decrypt : ";
				cin >> filename;

				cout << "Enter your 16 digit alphanumeric key to decrypt : ";
				cin >> key;

				cout << endl;

				Decrypt(filename, key);
				break;

			case 3:
				exit = true;
				break;

			default:
				cout << "\nWrong selection. Choose 1 to Encrypt, 2 to Decrypt or 3 to exit the program\n\n";
		}
	}
	return 0;
}

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
	ifstream fileEncrypt(fileName + ".txt");

	if (!fileEncrypt.is_open())
		cout << "The input file you want to encrypt does not exist\n\n";
	else
	{
		try
		{
		string fileData((istreambuf_iterator<char>(fileEncrypt)), (istreambuf_iterator<char>()));

		string encoded, decoded, cipher;

		ECB_Mode<AES>::Encryption encryption;
		encryption.SetKey((byte*)key.c_str(), sizeof(key));

		StringSource(fileData, true, new StreamTransformationFilter(encryption, new StringSink(cipher)));
		StringSource(cipher, true, new HexEncoder(new StringSink(encoded)));

		fileEncrypt.close();

		ofstream EncryptOut(fileName + ".Crypt");
		EncryptOut << encoded;
		EncryptOut.close();
		CreateHash(fileName, fileData);
		}
		 catch (Exception const& e)
		 {
			 cout << e.what() << endl;
			 return;
		 }
	}
}

void Decrypt(string fileName, string key)
{
	ifstream fileDecrypt(fileName + ".Crypt");

	if (!fileDecrypt.is_open())
		cout << "The input file you want to decrypt does not exist\n";
	else
	{
		 try
		 {
			string decoded, plainText;
			string fileData((istreambuf_iterator<char>(fileDecrypt)), (istreambuf_iterator<char>()));

			ECB_Mode<AES>::Decryption decryption;
			decryption.SetKey((byte*)key.c_str(), sizeof(key));
			StringSource(fileData, true, new HexDecoder(new StringSink(decoded)));
			StringSource(decoded, true, new StreamTransformationFilter(decryption, new StringSink(plainText)));

			fileDecrypt.close();

			ofstream DecryptOut(fileName + "1.txt");
			DecryptOut << plainText;

			DecryptOut.close();
		 }
		  catch (Exception const& e)
		 {
			 cout << e.what() << endl;
			 return;
		 }

		 ifstream hashFileOpen(fileName + ".hash");
		 string hashData((istreambuf_iterator<char>(hashFileOpen)), (istreambuf_iterator<char>()));
		 hashFileOpen.close();

		 ifstream fileOpen(fileName + "1.txt");
		 string hashFileData((istreambuf_iterator<char>(fileOpen)), (istreambuf_iterator<char>()));
		 fileOpen.close();
		

		 if(hashData.compare( CreateHash(fileName, hashFileData)) == 0)
			 cout << "Integrity is Intact\n";
		 else
			  cout << "Integrity has been compromised\n";
	}
}

string CreateHash(string fileName, string fileData)
{
	SHA512 hash;
	HexEncoder encoder;
	string output;

	byte hashSize[SHA512::DIGESTSIZE];
	hash.CalculateDigest(hashSize,(byte*)fileData.c_str(), fileData.length());
	
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(hashSize, sizeof(hashSize));
	encoder.MessageEnd();

	ofstream hashFile(fileName + ".hash");

	hashFile << output;

	hashFile.close();

	return output;
}