/*
File:       CryptAES.h
Written by: Oyedotun Oyesanmi
Date:       11/20/2015
Desc:       Definition file for encryption and decryption program.
*/

#pragma once
#include <iostream>
#include <string>

using namespace std;

/*
This function is used to repeatedly display MENU to the user. 
It is void and take no parameter
*/
void DisplayMenu();

/*
Encrypt function is used to encrypt string data from an input file.
This function takes two parameters: name of the file(which may be a full path to file, but without file extension.
Second parameter is the key that the encrption lib makes use of. Key has to be a 16-character parameter.
*/
void Encrypt(string fileName, string key);

/*
Decrypt function is used to decryt a string of Hex Encoded value gotten from a file.
This function takes two parameters: name of the file(may also be a full path to the file, but without the file extension.
Second parameter is the exact key used in encrypting the file, which has to obviously be a 16-char value.
*/
void Decrypt(string fileName, string key);

/*
This function writes data to file. 
The first parameter is the name of the file we want to write to (created if it doesnt exist).
Second parameter is the data we want to write to the file. 
Default file extension is .txt.
*/
void WriteToFile(string fileName, string data);

/*
This function is used to create a 64-bit hash value using SHA512.
It takes a string parameter for the data we want to hash, then returns a string of the hash.
*/
string CreateHash(string fileData);
