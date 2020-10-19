/* 
**********

Proyecto 2

Universidad Del Valle de Guatemala

Autores:
- Sofía Rueda			Carné: 19099
- Diego Ruiz			Carné: 18761
- Martín España 		Carné: 19258

Fecha de creación: 04/10/2020

última fecha de modificación: 18/10/2020
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
string const initialFileName = "FUENTE.txt";												//Nombre del archivo fuente 								(editable)
string const outputFileName = "salida.txt";													//Nombre del archivo de salida 								(editable)
string keyWord = "0100010000110011011001100100000001010101010011000101010001011111";		//Palabra binaria clave de cifrado predeterminada(default)	(editable)
string cypherDone = "";																		//Variable que almacenara el texto cifrado					(no editable)
string decypherDone = "";																	//Variable que almacenara el texto descifrado				(no editable)
int const bufferLength = 8;																	//Espacio del buffer (cuantas letras se cifran seguidas)	(¡¡¡peligroso editar!!!)
int const threadCount = 4;																	//Numero de threads utilizados								(editable)
string round_keys[2];																		//Llaves totales generadas									(no editable)
bool firstDone = false;

int initialPemutation[64] = {58, 50, 42, 34, 26, 18, 10, 2,
							 60, 52, 44, 36, 28, 20, 12, 4,
							 62, 54, 46, 38, 30, 22, 14, 6,
							 64, 56, 48, 40, 32, 24, 16, 8,
							 57, 49, 41, 33, 25, 17,  9, 1,
							 59, 51, 43, 35, 27, 19, 11, 3,
							 61, 53, 45, 37, 29, 21, 13, 5,
							 63, 55, 47, 39, 31, 23, 15, 7};

/*----- Variables globales compartidas -----*/
int counter = 0;
pthread_mutex_t muteX;
pthread_cond_t firstGroupPrinted;

/***************************************************************
Subrutina para leer el archivo fuente y convertirlo a un string
***************************************************************/
string readFile(string fileName){
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

/***********************************************
Subrutina para convertir un string en ascii a un string en binario.
Por ejemplo: "Hola" -> "01001000011011110110110001100001"
***********************************************/
string asciiToBinary(string letter){

	char c;
	int binary[8], j, times = 0;
	vector<int> collection;
	string result;

	for (int i = 0, len = letter.size(); i < len; ++i ) {
		c = letter[i], j = 0;
		while ( c > 0 ) {
			binary[j++] = c & 1;
			c >>= 1; // bit-shift right (int divide by 2)
		}
		while ( j < 8 ) { // Pad with leading 0s to conform to 8-bit standard.
			binary[j++] = 0;
		}
		while ( j > 0) { // Read the int array backwards.
			collection.push_back(binary[--j]);
		}
	}
	
	for(int i=0; i<collection.size();i++){
		result += to_string(collection[i]);
	}

	return result;
}

// Funcion para convertir un numero decimal a uno en binario
string convertDecimalToBinary(int decimal)
{
    string binary;
    while(decimal != 0) {
        binary = (decimal % 2 == 0 ? "0" : "1") + binary; 
        decimal = decimal/2;
    }
    while(binary.length() < 4){
        binary = "0" + binary;
    }
    return binary;
}

// Function to convert a number in binary to decimal
int convertBinaryToDecimal(string binary)
{
    int decimal = 0;
    int counter = 0;
    int size = binary.length();
    for(int i = size-1; i >= 0; i--)
    {
        if(binary[i] == '1'){
            decimal += pow(2, counter);
        }
    counter++;
    }
    return decimal;
}

// Function to do a circular left shift by 1
string shift_left_once(string key_chunk){ 
    string shifted="";  
        for(int i = 1; i < 28; i++){ 
            shifted += key_chunk[i]; 
        } 
        shifted += key_chunk[0];   
    return shifted; 
} 

// Function to do a circular left shift by 2
string shift_left_twice(string key_chunk){ 
    string shifted=""; 
    for(int i = 0; i < 2; i++){ 
        for(int j = 1; j < 28; j++){ 
            shifted += key_chunk[j]; 
        } 
        shifted += key_chunk[0]; 
        key_chunk= shifted; 
        shifted =""; 
    } 
    return key_chunk; 
}

//Subrutina para inicializar las mutex y las condiciones
void init() 
{
    pthread_mutex_init(&muteX, NULL);
    pthread_cond_init(&firstGroupPrinted, NULL);
}


// Function to compute xor between two strings
string Xor(string a, string b){ 
	string result = ""; 
	int size = b.size();
	for(int i = 0; i < size; i++){ 
		if(a[i] != b[i]){ 
			result += "1"; 
		}
		else{ 
			result += "0"; 
		} 
	} 
	return result; 
} 


void createKeys(){
	
	string key = asciiToBinary(keyWord);
	// The PC1 table
    int pc1[56] = {
    57,49,41,33,25,17,9, 
    1,58,50,42,34,26,18, 
    10,2,59,51,43,35,27, 
    19,11,3,60,52,44,36,         
    63,55,47,39,31,23,15, 
    7,62,54,46,38,30,22, 
    14,6,61,53,45,37,29, 
    21,13,5,28,20,12,4 
    };
    // The PC2 table
    int pc2[48] = { 
    14,17,11,24,1,5, 
    3,28,15,6,21,10, 
    23,19,12,4,26,8, 
    16,7,27,20,13,2, 
    41,52,31,37,47,55, 
    30,40,51,45,33,48, 
    44,49,39,56,34,53, 
    46,42,50,36,29,32 
	}; 
	
	string perm_key =""; 
	for(int i = 0; i < 56; i++){ 
		perm_key+= key[pc1[i]-1]; 
	} 
	// 2. Dividing the key into two equal halves
	string left= perm_key.substr(0, 28); 
	string right= perm_key.substr(28, 28); 
	for(int i=0; i<2; i++){ 
		// 3.1. For rounds 1, 2, 9, 16 the key_chunks
		// are shifted by one.
		if(i == 0 || i == 1){
			left= shift_left_once(left); 
			right= shift_left_once(right);
		} 
		// 3.2. For other rounds, the key_chunks
		// are shifted by two
		else{
			left= shift_left_twice(left); 
			right= shift_left_twice(right);
		}
		// Combining the two chunks
		string combined_key = left + right;
		string round_key = ""; 
		// Finally, using the PC2 table to transpose the key bits
		for(int i = 0; i < 48; i++){ 
			round_key += combined_key[pc2[i]-1]; 
		}   
		round_keys[i] = round_key; 
	} 
}

/*****************************************************************************************
Subrutina para cifrar un string de 8 caracteres (Aquí se utiliza el XOR con cada pthread)
*****************************************************************************************/

void *cypherText(void *argument){
	
	string &oldString = *(static_cast<string*>(argument));
	oldString = asciiToBinary(oldString);
	
	// The initial permutation table 
    int initial_permutation[64] = { 
    58,50,42,34,26,18,10,2, 
    60,52,44,36,28,20,12,4, 
    62,54,46,38,30,22,14,6, 
    64,56,48,40,32,24,16,8, 
    57,49,41,33,25,17,9,1, 
    59,51,43,35,27,19,11,3, 
    61,53,45,37,29,21,13,5, 
    63,55,47,39,31,23,15,7 
    }; 
    // The expansion table
    int expansion_table[48] = { 
    32,1,2,3,4,5,4,5, 
    6,7,8,9,8,9,10,11, 
    12,13,12,13,14,15,16,17, 
    16,17,18,19,20,21,20,21, 
    22,23,24,25,24,25,26,27, 
    28,29,28,29,30,31,32,1 
    }; 
    // The substitution boxes. The should contain values
    // from 0 to 15 in any order.
    int substition_boxes[8][4][16]=  
    {{ 
        14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 
        0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8, 
        4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 
        15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 
    }, 
    { 
        15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 
        3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5, 
        0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 
        13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 
    }, 
    { 
        10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 
        13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1, 
        13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 
        1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 
    }, 
    { 
        7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 
        13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9, 
        10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 
        3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 
    }, 
    { 
        2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 
        14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6, 
        4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 
        11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 
    }, 
    { 
        12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 
        10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8, 
        9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 
        4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 
    }, 
    { 
        4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 
        13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6, 
        1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 
        6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 
    }, 
    { 
        13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 
        1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2, 
        7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 
        2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 
    }};
	
	// The permutation table
    int permutation_tab[32] = { 
    16,7,20,21,29,12,28,17, 
    1,15,23,26,5,18,31,10, 
    2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25 
    }; 
    // The inverse permutation table
    int inverse_permutation[64]= { 
    40,8,48,16,56,24,64,32, 
    39,7,47,15,55,23,63,31, 
    38,6,46,14,54,22,62,30, 
    37,5,45,13,53,21,61,29, 
    36,4,44,12,52,20,60,28, 
    35,3,43,11,51,19,59,27, 
    34,2,42,10,50,18,58,26, 
    33,1,41,9,49,17,57,25 
    };
	
	string perm = ""; 
    for(int i = 0; i < 64; i++){ 
        perm += oldString[initial_permutation[i]-1]; 
    }  
    // 2. Dividing the result into two equal halves 
    string left = perm.substr(0, 32); 
    string right = perm.substr(32, 32);
    // The plain text is encrypted 16 times  
    for(int i=0; i<2; i++) { 
        string right_expanded = ""; 
        // 3.1. The right half of the plain text is expanded
        for(int i = 0; i < 48; i++) { 
            right_expanded += right[expansion_table[i]-1]; 
    };  // 3.3. The result is xored with a key
        string xored = Xor(round_keys[i], right_expanded);  
        string res = ""; 
        // 3.4. The result is divided into 8 equal parts and passed 
        // through 8 substitution boxes. After passing through a 
        // substituion box, each box is reduces from 6 to 4 bits.
        for(int i=0;i<8; i++){ 
            // Finding row and column indices to lookup the
            // substituition box
            string row1= xored.substr(i*6,1) + xored.substr(i*6 + 5,1);
            int row = convertBinaryToDecimal(row1);
            string col1 = xored.substr(i*6 + 1,1) + xored.substr(i*6 + 2,1) + xored.substr(i*6 + 3,1) + xored.substr(i*6 + 4,1);;
            int col = convertBinaryToDecimal(col1);
            int val = substition_boxes[i][row][col];
            res += convertDecimalToBinary(val);  
        } 
        // 3.5. Another permutation is applied
        string perm2 =""; 
        for(int i = 0; i < 32; i++){ 
            perm2 += res[permutation_tab[i]-1]; 
        }
        // 3.6. The result is xored with the left half
        xored = Xor(perm2, left);
        // 3.7. The left and the right parts of the plain text are swapped 
        left = xored; 
        if(i < 2){ 
            string temp = right;
            right = xored;
            left = temp;
        } 
    } 
    // 4. The halves of the plain text are applied
    string combined_text = left + right;   
    string ciphertext =""; 
    // The inverse of the initial permuttaion is applied
    for(int i = 0; i < 64; i++){ 
        ciphertext+= combined_text[inverse_permutation[i]-1]; 
    }
	
	pthread_mutex_lock(&muteX);
	//pthread_cond_wait(&firstGroupPrinted, &muteX);
	cypherDone += ciphertext;
	pthread_mutex_unlock(&muteX);
	
	return NULL;
}

//Main
int main(){
	
	//Inicialización de variables
	int rc;
	int option;
	string text;
	bool active = true;
	bool hasCypheredFirst = false;
	string fileName = "FUENTE.txt";
	
	//Se lee el archivo
	text = readFile(fileName);
	
	
	//Se inicializan las variables de pthread, de mutex y de cond
	
	pthread_mutex_t mutexList[threadCount]; //Se crea un array de mutex para las mutex de cada hilo
	
	for(int k=0;k<threadCount;k++){
		pthread_mutex_t obj;
		mutexList[k] = obj;
	}
	
	pthread_cond_t condList[threadCount]; //Se crea un array de condiciones para las condiciones de cada hilo
	
	for(int l=0;l<threadCount;l++){
		pthread_cond_t obj;
		condList[l] = obj;
	}
	
	pthread_t cypher_thread[threadCount];
	
	
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
				hasCypheredFirst = true;
				cypherDone = "";			//Se vacía el texto cifrado en caso deseen repetir el proceso
				string temporary = "";		//Variable que sirve para separar el texto
				int letterGroups;			//Cantidad de grupos de 8 caracteres que se formaran a partir del texto
				int a = 0; 					//Contador de las 8 letras
				int rept;					//Contador de las repeticiones (1-8)
				
				string password;
				bool incorrect = true;
				string nothing;
				
				while(incorrect){
					cout<<"Por favor, ingrese una palabra clave de "<<bufferLength<<" caracteres para cifrar y descifrar el texto: ";
					cin>>password;
					cout<<endl;
					
					if(password.length() == bufferLength){
						keyWord = asciiToBinary(password);
						incorrect = false;
					}
					else{
						if(password.length() > bufferLength){
							cout<<"La contraseña ingresada tiene más de "<<bufferLength<<" caracteres... Intente nuevamente."<<endl;
						}
						else if(password.length() < bufferLength){
							cout<<"La contraseña ingresada tiene menos de "<<bufferLength<<" caracteres... Intente nuevamente."<<endl;
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
				
				/******************************************************************************************************
				IMPORTANTE: EN ESTE PUNTO, TODOS LOS GRUPOS DE "BufferLength" CARACTERES ESTAN EN EL ARRAY "COLLECTION"
				*******************************************************************************************************/
				
				//Se crea un vector con los grupos de caracteres (STACK)
				vector<string> stack;
				for(int i=0;i<letterGroups;i++){
					stack.push_back(collection[i]);
				}
				
				/***********************************************************************************************
				Se deben crear las llaves que se utilizaran en la encriptación.
				***********************************************************************************************/
				createKeys();
				
				/***********************************************************************************************
				Se asigna un grupo de 8 caracteres a cada thread hasta que se agoten los grupos de 8 caracteres.
				Para ello se utiliza la estructura de datos "stack" a través de un vector.
				***********************************************************************************************/
				while(stack.size()>0){
					for(int j=0;j<threadCount && stack.size()>0;j++){
						
						muteX = mutexList[j];
						firstGroupPrinted = condList[j];
						
						init();
						
						temporary = stack.front();
						stack.erase(stack.begin());

						//operate temporary
						//string temporalCode = asciiToBinary(temporary);
						
						//SE DEBE LLAMAR A LA FUNCION DE CIFRADO
						rc = pthread_create(&cypher_thread[j],NULL,cypherText,static_cast<void*>(&temporary));
						usleep(1000);
						
						//Se verifica que no hubo errores
						if(rc){
							printf("ERROR; return code from pthread_create() is %d\n", rc);
							exit(-1);
						}
						
						//Se espera a que el thread termine
						rc = pthread_join(cypher_thread[j], NULL);
						
						//Se verifica que no hubo errores
						if(rc){
							printf("ERROR; return code from pthread_join() is %d\n", rc);
							exit(-1);
						}
						
						
					}
				}
				//********************************************************/
				
				cout<<endl;
				
				
				//**********************************************************
				//Se crea el archivo de salida y se escribe el texto cifrado
				ofstream outFile(outputFileName,ios::out);
				if(!outFile)
				{
					cerr<<"Error al crear "<<outputFileName<<endl;
					exit(EXIT_FAILURE);
				}
				outFile<<cypherDone;
				//**********************************************************
				
				
			}
			//Si sobrevive hasta aca, la operación fue exitosa
			cout<<"El texto se ha cifrado exitosamente."<<endl;
		}
		else if(option == 2 && hasCypheredFirst){
			string desPassword;
			decypherDone = "";			//Se vacía el texto cifrado en caso deseen repetir el proceso
			string temporary = "";		//Variable que sirve para separar el texto
			int letterGroups;			//Cantidad de grupos de 8 caracteres que se formaran a partir del texto
			int a = 0; 					//Contador de las 8 letras
			int rept;					//Contador de las repeticiones (1-8)
			
			cout<<"Por favor, ingrese la contraseña para iniciar el descifrado: ";
			cin>>desPassword;
			cout<<endl;
			
			if(asciiToBinary(desPassword) == keyWord){
				//Se descifra el texto de "salida.bin"
				string text_two = readFile(outputFileName);
				
				if(text==""){
					cout<<"El archivo "<<outputFileName<<" esta vacio. Debe cifrar el texto antes de descifrarlo."<<endl;
				}
				else{
					//Se determina cuantos grupos de caracteres se crearan a partir del tamaño del buffer definido
					if(((text.length())%bufferLength)>0){
						letterGroups = (int)(text.length()/bufferLength)+1;
					}
					else{
						letterGroups = (int)(text.length()/bufferLength);
					}
					
					//Se crea el array de la longitud de cantidad de grupos de 8 caracteres
					string collection [letterGroups];
					decypherDone = asciiToBinary(text);
					
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
					
					/******************************************************************************************************
					IMPORTANTE: EN ESTE PUNTO, TODOS LOS GRUPOS DE "BufferLength" CARACTERES ESTAN EN EL ARRAY "COLLECTION"
					*******************************************************************************************************/
					
					//Se crea un vector con los grupos de caracteres (STACK)
					vector<string> stack;
					for(int i=0;i<letterGroups;i++){
						stack.push_back(collection[i]);
					}
					
					//Se crean las llaves en caso de no haberse creado y se invierten para descifrar
					string x, y, z;
					x = round_keys[0];
					y = round_keys[1];
					z = round_keys[2];
					
					round_keys[0] = z;
					round_keys[1] = y;
					round_keys[2] = x;
					
					/*********************************************************************************
					Se reinicia la variable donde se almacenara el texto descifrado
					*********************************************************************************/
					cypherDone = "";
					
					/***********************************************************************************************
					Se asigna un grupo de 8 caracteres a cada thread hasta que se agoten los grupos de 8 caracteres.
					Para ello se utiliza la estructura de datos "stack" a través de un vector.
					***********************************************************************************************/
					while(stack.size()>0){
						for(int j=0;j<threadCount && stack.size()>0;j++){
							
							muteX = mutexList[j];
							firstGroupPrinted = condList[j];
						
							init();
							
							temporary = stack.front();
							stack.erase(stack.begin());

							//operate temporary
							//string temporalCode = asciiToBinary(temporary);
							
							//SE DEBE LLAMAR A LA FUNCION DE CIFRADO
							rc = pthread_create(&cypher_thread[j],NULL,cypherText,static_cast<void*>(&temporary));
							usleep(1000);
							
							//Se verifica que no hubo errores
							if(rc){
								printf("ERROR; return code from pthread_create() is %d\n", rc);
								exit(-1);
							}
							
							//Se espera a que el thread termine
							rc = pthread_join(cypher_thread[j], NULL);
							
							//Se verifica que no hubo errores
							if(rc){
								printf("ERROR; return code from pthread_join() is %d\n", rc);
								exit(-1);
							}
							
							
						}
					}
					//********************************************************/
					
					cout<<"El texto descifrado en binario es el siguiente: "<<endl;
					
					int newBuffer, extras = 0, reptCounter = 0, lineCounter = 0;
					if((decypherDone.size())%bufferLength == 0){
						newBuffer = decypherDone.size()/bufferLength;
					}
					else{
						extras = (decypherDone.size())%bufferLength;
						newBuffer = ((decypherDone.size()-((decypherDone.size())%bufferLength))/bufferLength)+1;
					}
					
					for(int i=0;i<decypherDone.size() && newBuffer>0;i++){
						cout<<decypherDone[i];
						reptCounter++;
						
						if(reptCounter == bufferLength){
							cout<<" ";
							lineCounter++;
							reptCounter = 0;
						}
						if(lineCounter == bufferLength){
							cout<<endl;
							lineCounter = 0;
						}
						
					}
					cout<<endl;
					cout<<"Que se traduce a : \n"<<text<<endl;
					
				}
				
			}
			else{
				cout<<"CONTRASEÑA INCORRECTA. SI OLVIDO LA CONTRASEÑA DEBERA REINICIAR EL PROGRAMA."<<endl;
			}
		}
		else if(option == 2 && !hasCypheredFirst){
			cout<<"Debe cifrar antes de descifrar..."<<endl;
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
