/*
File:       main.cpp
Written by: Oyedotun Oyesanmi
Date:       11/20/2015
Desc:       Main program interface.
*/


#include <iostream>
#include "CryptAES.h"
using namespace std;

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
