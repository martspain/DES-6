/* 
**********

Proyecto 2

Universidad Del Valle de Guatemala

Autores:
- Sofía Rueda			Carné: 19099
- Diego Ruiz			Carné: 18761
- Martín España 		Carné: 19258

Fecha de creación: 04/10/2020

**********

Proyecto 2: Cifrado y Descifrado de Textos DES

**********
*/

#include <iostream>
#include <stdio.h>		//printf
#include <cstdlib>		//rand
#include <cmath>		//pow
#include <ctime>		//time_t, clock, difftime
#include <pthread.h>	//treads
#include <fstream> 		//file processing
#include <stdlib.h>		//binary convertion
#include <string>		//string usage
#include <sstream>		//string input/output
#include <vector>		//dinamic arrays
#include <unistd.h>		//usleep
#include <bitset>		//binary convertion
#include <semaphore.h>  //semaphore 
//#include <mpi.h>

using namespace std;

/*******************
Variables globales
*******************/
string const fileName = "FUENTE.txt";	//Nombre del archivo fuente 								(editable)
string keyWord = "D3fT";				//Palabra clave de cifrado predeterminada (default)			(editable)
string cypherDone = "";					//Variable que almacenara el texto cifrado					(no editable)
int const bufferLength = 8;				//Espacio del buffer (cuantas letras se cifran seguidas)	(¡¡¡peligroso editar!!!)
int const threadCount = 4;				//Numero de threads utilizados								(editable)
int initialPemutation[64] = {58, 50, 42, 34, 26, 18, 10, 2,
							 60, 52, 44, 36, 28, 20, 12, 4,
							 62, 54, 46, 38, 30, 22, 14, 6,
							 64, 56, 48, 40, 32, 24, 16, 8,
							 57, 49, 41, 33, 25, 17,  9, 1,
							 59, 51, 43, 35, 27, 19, 11, 3,
							 61, 53, 45, 37, 29, 21, 13, 5,
							 63, 55, 47, 39, 31, 23, 15, 7};
vector<int> binaryCollection;

/*----- Variables globales compartidas -----*/
int counter = 0;
pthread_cond_t cola_llena, cola_vacia; 
pthread_mutex_t mutex_forvar; 
sem_t count_sem, barrier_sem, done_sem;


/***************************************************************
Subrutina para leer el archivo fuente y convertirlo a un string
***************************************************************/
string readFile(){
	//Se crea el stream para leer el archivo fuente
	ifstream fileStream(fileName,ios::in);
	
	//Si hay errores al leer el archivo, e.g. no se encuentra el archivo se cancela la operacion.
	if(!fileStream)
	{
		cerr<<"Error al leer "<<fileName<<endl;
		exit(EXIT_FAILURE);
	}
	
	//Variale que contendra el texto
	string result;
	
	if(fileStream){
		ostringstream receiver;
		receiver<<fileStream.rdbuf();
		result =receiver.str();
	}
	
	return result;
}


/*****************************************************************************************
Subrutina para cifrar un string de 8 caracteres (Aquí se utiliza el XOR con cada pthread)
*****************************************************************************************/
/*
void *cypherText(void *argument){
	
	
}
*/

void binaryConvert(string letter){

	char c;

	int binary[8], j, times = 0;

	for ( int i = 0, len = letter.size(); i < len; ++i ) {

		c = letter[i], j = 0;

		while ( c > 0 ) {

			binary[j++] = c & 1;

			c >>= 1; // bit-shift right (int divide by 2)

		}

		while ( j < 8 ) { // Pad with leading 0s to conform to 8-bit standard.

			binary[j++] = 0;

		}

		while ( j > 0) { // Read the int array backwards.

			binaryCollection.push_back(binary[--j]);

		}

		if ( ! (++times % 4) ) {
			//Nothing

		}

		else {

			//Nothing

		}

	}
	
}



//Main
int main(){
	
	//Inicialización de variables
	int rc;
	int option;
	string text;
	bool active = true;
	
	//Se lee el archivo
	text = readFile();
	
	/*
	//Se inicializan las variables de pthread, de mutex y de cond
	pthread_t threadID;
	pthread_mutex_init(&mutex_forvar, NULL);
	pthread_cond_init(&cola_llena, NULL); 
	pthread_cond_init(&cola_vacia, NULL);
	*/
	
	//Se muestra el banner del programa.
	cout<<"Universidad del Valle de Guatemala"<<endl;
	cout<<"Programación de Microprocesadores"<<endl;
	cout<<"Proyecto 2: Cifrado y Descifrado de Textos DES"<<endl;
	cout<<"Autores: \nSofía Rueda	Carné: 19099"<<endl;
	cout<<"Diego Ruiz	Carné: 18761 \nMartín España	Carné: 19258"<<endl;
	
	while(active){
		//Se muestra el menu y se solicita una opción.
		cout<<"\nMenu de Opciones \n¿Qué desea hacer? \n1. Cifrar texto. \n2. Descifrar texto \n3. Salir."<<endl;
		cin>>option;
		
		//Si se elige cifrar el texto...
		if(option == 1){
			if(text==""){
				cout<<"El archivo "<<fileName<<" esta vacio."<<endl;
			}
			else{
				cypherDone = "";			//Se vacía el texto cifrado en caso deseen repetir el proceso
				string temporary = "";		//Variable que sirve para separar el texto
				int letterGroups;			//Cantidad de grupos de 8 caracteres que se formaran a partir del texto
				int a = 0; 					//Contador de las 8 letras
				int rept;					//Contador de las repeticiones (1-8)
				
				string password;
				bool incorrect = true;
				
				while(incorrect){
					cout<<"Por favor, ingrese una palabra clave de 4 caracteres para cifrar y descifrar el texto: ";
					cin>>password;
					cout<<endl;
					
					if(password.length() == 4){
						keyWord = password;
						incorrect = false;
					}
					else{
						if(password.length() > 4){
							cout<<"La contraseña ingresada tiene más de 4 caracteres... Intente nuevamente."<<endl;
						}
						else if(password.length() < 4){
							cout<<"La contraseña ingresada tiene menos de 4 caracteres... Intente nuevamente."<<endl;
						}
					}
				}
				
				//Se determina cuantos grupos de caracteres se crearan a partir del tamaño del buffer definido
				if(((text.length())%bufferLength)>0){
					letterGroups = (int)(text.length()/bufferLength)+1;
				}
				else{
					letterGroups = (int)(text.length()/bufferLength);
				}
				
				//Se crea el array de la longitud de cantidad de grupos de 8 caracteres
				string collection [letterGroups];
				
				//Se recorre el texto y se separa en sus respectivos grupos, los cuales se almacenan en collection
				for(int i=0;i<letterGroups;i++){
					rept = 0;
					
					//Si se estan comparando las últimas letras esto asegura que no va a sobrepasar el limite del texto (out of bounds prevention)
					if((a+bufferLength-1)>(text.length()-1)){
						while(rept < bufferLength && (a+rept)<(text.length()-1)){
							temporary += text[a+rept];
							rept++;
						}
					}
					
					//Si se comparan las letras de cualquier otra parte del texto se pueden separar normalmente
					else{
						while(rept < bufferLength){
							temporary += text[a+rept];
							rept++;
						}
					}
					
					collection[i] = temporary;
					a+=bufferLength;
					temporary = "";
				}
				
				/*****************************************************************************************
				IMPORTANTE: EN ESTE PUNTO, TODOS LOS GRUPOS DE 8 CARACTERES ESTAN EN EL ARRAY "COLLECTION"
				*****************************************************************************************/
				
				//Se crea un vector con los grupos de caracteres (STACK)
				vector<string> stack;
				for(int i=0;i<letterGroups;i++){
					stack.push_back(collection[i]);
				}
				
				/***********************************************************************************************
				Se asigna un grupo de 8 caracteres a cada thread hasta que se agoten los grupos de 8 caracteres.
				Para ello se utiliza la estructura de datos "stack" a través de un vector.
				***********************************************************************************************/
				while(stack.size()>0){
					for(int j=0;j<threadCount && stack.size()>0;j++){
						
						temporary = stack.front();
						stack.erase(stack.begin());

						//operate temporary
						binaryConvert(temporary);
						
						
					}
				}
				//********************************************************/
				
				
				/*
				Se muestra en binario el texto extraido del txt
				
				for(int i = 0; i<binaryCollection.size(); i++){
					cout<<binaryCollection[i];
					if(!((i+1)%8)){
						cout<<" ";
					}
					if(!((i+1)%32)){
						cout<<endl;
					}
				}
				*/
				
				
				//**********************************************************
				//Se crea el archivo de salida y se escribe el texto cifrado
				ofstream outFile("salida.bin",ios::binary);
				if(!outFile)
				{
					cerr<<"Error al crear salida.bin"<<endl;
					exit(EXIT_FAILURE);
				}
				outFile<<cypherDone;
				//**********************************************************
				
			}
			//Si sobrevive hasta aca, la operación fue exitosa
			cout<<"El texto se ha cifrado exitosamente."<<endl;
		}
		else if(option == 2){
			string desPassword;
			cout<<"Por favor, ingrese la contraseña para iniciar el descifrado: ";
			cin>>desPassword;
			cout<<endl;
			
			if(desPassword == keyWord){
				//Se descifra el texto de "salida.bin"
			}
			else{
				cout<<"CONTRASEÑA INCORRECTA. SI OLVIDO LA CONTRASEÑA DEBERA REINICIAR EL PROGRAMA."<<endl;
			}
		}
		//Si se elige salir del programa...
		else if(option == 3){
			cout<<"Gracias por utilizar el programa. ¡Vuelva pronto!"<<endl;
			active = false;
		}
		
		//Si ingresan una opción no valida...
		else{
			cout<<"Por favor, ingrese una opción válida"<<endl;
		}
	}

	exit(0);
}
