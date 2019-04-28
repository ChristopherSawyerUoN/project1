/*
 * Christopher Sawyer
 * 3181689@uon.edu.au
 * 
 * Project 1
 * implimentation of a Caesar cypher (Rotation Cipher)
 * implimentation of a substitution cipher
 * 
 * this program will perform:
 * 1. Encryption - given an algorithm message and a key
 * 2. Decryption - given an algorithm message and a key
 * 3. Decryption - given cipher text and some assumptions of its contents without a key
 * 
 * 1. ROTATION CIPHER
 * consider the alphabet:
 *  ABCDEFGHIJKLMNOPQRSTUVWXYZ
 * with a rotation key of 1 - everything is moved to the right by 1 letter
 *  ZABCDEFGHIJKLMNOPQRSTUVWXY
 * An Example of this type of Encryption would be
 *  Message: ATTACK AT SUNRISE
 *  Cipher : ZSSZBJ ZS RTMQHRD
 * Mathematically the cipher can be described using the Modulus operator.
 * The Key is an integer, k, and between -25 and 25 (0 and 26 imply "no encryption")
 *  a = 0, b = 1, c = 2, ..., z = 25
 * To encrypt the letter m in the message - use a function e(m)
 *  e(x) = (m + k)(mod 26)
 * to decrypt the letter c in the cipher text - use the function e(c)
 *  e(x) = (c - k)(mod 26)
 * NOTE: the modulus opperator cannot deal with a negative number
 *          If a negative number occurs in the calculation (m + k) or (c - k)
 *          then add 26 to make the number positive without impacting the result
 *
 *  1.1 ROTATION CIPHER ATTACKS
 * There are only 25 different subsitutions that can be made that can lead to a decryption of the cipher text
 * 26 being no rotation. a full decryption is possible from finding just one letter subsitution.
 * Decryption WITHOUT the key can be done though two methods:
 *  Brute Force Attack - every key is tested and all algorith outputs are tested for intelligibility or
 *      searched for some known phrase (like a name)
 *  Statistical Attack - each different letter in the cipher text is counted, the most frequent letter
 *      assumed to be "e" (or "t" then "a"), the rotation deduced and tested from that.
 * 
 * 2. SUBSTITUTION CIPHER
 * this cipher works by replacing all 26 letters of the alphabet with new substituted letters
 * Each letter is chosen once, the key is therefore knowledge of all 26 different subsitutions.
 * the possible number of key combinations is 26! = 4x10^26 combinations
 * Example:
 *  Message:    ABCDEFGHIJKLMNOPQRSTUVWXYZ
 *  Cipher Text:QWERTYUIOPASDFGHJKLZXCVBNM
 * An Example of this type of Encryption would be:
 *  Message:    PLEASE GET MILK AT THE SHOPS
 *  Cipher Text:HSTQLT UTZ DOSA QZ ZIT LIGHL
 * Expressing this mathematically is not possible, this method is more akin to a lookup table
 * where each letter, xn, becomes a different letter, yn, based on the fixed subsitution rule.
 * 
 * 2.1 SUBSTITUTION CIPHER ATTACKS
 * Brute Force Attack - not posible, there are far too many variations of the key to test them all
 * Statistical Attack - estimate which letters are were used for "e", "t", "a", "z", ...etc.
 *      If assumed that the message is in normal English text then other assumtions can be made.
 *      Any single letter word is likly to be "a" or "i"
 *      Likewise the most common three letter words is "the"
 *      By making educated guesses about common short words and letters a subset of the encrytpion can be deduced.
 *      Couple this with a dictionary and a "spell checker" (eg: Levenshtein Distance) can attempt further letter substitutions
 * 
 * 3. PROGRAMMING TASKS
 * Project 1 requires that this program will complete these taks:
 *      1. Encryption of a message with a rotation cipher given the message text and rotation amount
 *      2. Decryption of a message encrypted with a rotation cipher given the cipher text and rotation amount
 *      3. Encryption of a message with a substitution cipher given the message text and alphabet substitution
 *      4. Decryption of a message encrypted with a substitution cipher given the cipher text and substitutions
 *      5. Decryption of a message encrypted with a rotation cipher given the cipher text only
 *      6. Decryption of a message encrytped with a substitution cipher given the cipher text only
 * 
 * 3.1 INPUTS
 * All data inputs (message, keys, cipher text, algorithm selection, etc) must either:
 *  - hard-coded variable initialisation                        - Use this at the start of the project
 *  - read from stdin with scanf()
 *  - read from a file using the C standard file I/O library    - Use this as a final feature
 * 
 * 3.1.2 OUTPUTS
 * All program outputs should be sent to stdout
 * File I/O is encouraged, Use Both
 * 
 * 3.1.3 TASK SELECTION
 * Take user input from stdin to select each task in a menu system
 * (Advanced) Define the task as part of a header inside an input file which contains the message and key(or key and cipher text, or just cipher text)
 *      - A single integer placed on the first line to indicate the task to be performed, followed by
 *      - A 2nd, optional line which contains a key (start the line with a weird character like # to indicate that it is a key), followed by
 *      - the message or cipher text
 * 
 * 3.2 MESSAGE TEXT SPECIFICATION
 * the ciphers are only defined as letters
 *  - what should be done to punctuation and white space?
 *  - what about numerals
 *  - should upper and lower case letters be handeled differnetly
 * Follow these RULES:
 *  1. Do Not encrypt white space, punctuation, or numerals, if an innput character is not a letter is should be copied to the output unmodified
 *  2. All input data should use UPPER CASE letters only
 *      (Advanced) If a lowercase letter is found it should be converted to upper case before encryption
 * 
 * 3.3 KEY FORMAT SPECIFICATION
 * The rotation cipher is to be a single integer in the range of [0,26]. Encryption with a shift of 0 should process the plain text but produce
 *      cipher text equal to the plain text.
 * The substitution cipher key is a string of 26 UPPER CASE letters ordered as-per their alphabetical substitution
 * 
 * 3.3.1 ASCII CODE
 * All input data is to be encoded with the ASCII standard, All letters are stored as 8-bit integers
 *  if an input byte is outside the ranges [65,90] and [97,122] then it can be copied to the output
 *      without modification. If an input byte is in the lower case range [97,122], then subtract 32
 *      from its value to make it an upper case letter prior to encryption
 * 
 */

#include <stdio.h>
void program1Encrypt(void); //Message Encrypt Program
void program2Decrypt(void); //Message Decryption Program
void program3Decode(void);  //Decode Message using a Dictionary
void program4Exit(void);    //Exit Program - Housekeeping
void stringToUpper(char []); //String Lowercase to Uppercase Converter
void reorderAlpha(int key,char [],char []); //Reorder the string based on a key value rotating the string

int main(void){
    /*Menu
    Prompt user for a choice
    CASE 1: Encrypt a message
            recieve message text and key
    CASE 2: Decrypt a message
            recieve cipher text and key
    CASE 3: Decrypt a message
            recieve cipher text and use a dictionary to decrypt a message with no key
    CASE 4: EXIT
    */

    int  menu;
    
    while(menu != 4){
        printf("\nEnter a number to prefrom an action\n");
        printf("1 - to encrypt a message with a key\n");
        printf("2 - to decrypt a message with a key\n");
        printf("3 - to decrypt a cipher with a dictionary\n");
        printf("4 - to exit\n\n");
    
        printf("Enter your selection: ");
        scanf("%d",&menu); //scan in option here. 
        while(menu < 1 || menu > 4){
            printf("Invalid Choice - Please Try Again: ");
            scanf("%d",&menu);
        }
        
        
        switch(menu){
            case 1: program1Encrypt();break;
            case 2: program2Decrypt();break;
            case 3: program3Decode();break;
            case 4: program4Exit();break;
        }   
    
    }
   return 0;
}
 


//==============================================================================================================================================
// Program 1 Encrypt A Message using a rotation Cipher
void program1Encrypt(void){
    
    int MAXSTRING = 100;
    
    //ititalise the alphabet into an array
    char alpha[26] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
    char cipherAlpha[MAXSTRING];
    char messageText[] = "this is my message";
    char encryptedMessage[MAXSTRING];
    int  key;
    
    //print all elements in the array
    for(int i = 0; i < 26; i++){
        printf("%c ",alpha[i]);
    }    
    printf("\n");

    
    printf("Enter a Key: ");
    scanf("%d",&key);
    //Check that this number is positve
    while(key < 0){
        printf("Try again (use a positive number): ");
        scanf("%d",&key);
    }
    
    //Create the cipher Alphabet 
    reorderAlpha(key,alpha,cipherAlpha);  //Put the alphabet into the new order required by the key

    //Print the New Alphabet
    //print all elements in the array
    printf("The Cipher Alphabet: \n");
    for(int i = 0; i < 26; i++){
        printf("%c ",cipherAlpha[i]);
    }    

    printf("\n\n--> ");
    
    
    //enter the message text
    printf("Enter the message that will be encrypted: \n");
    //scanf("%s",messageText);                                          //uncomment this to enable manual entry of message text
    
    
    //print the message text
    printf("You Entered: \n-->");
    printf("%s \n",messageText);
    
    //convert the message text to uppercase
    printf("Now converted into uppercase:\n--> ");
    stringToUpper(messageText);
    
    //print the message text now in UPPERCASE
    printf("%s\n", messageText);
    
    //Encrypt the Message
    //compare each letter in the message to its counterpart in the new alphabet
    //step through each letter in the message and add its deciphered version to the array encryptedMessage
    //FOR
    // each letter of the string
    // check it against the alphabet
    // store its encrypted counterpart in the array encryptedMessage
    // then move on to the next letter
    // untill all are encrypted

    //print the now encrypted message
    printf("\nThis is the encrypted message: \n");

    for(int i = 0; i <= sizeof(messageText);i++){
        //loop through each letter in the messageText
        //printf("%c",messageText[i]);
        //find a match to the letter in the alphabet        
        if(messageText[i] || 32){       //not a space
            for(int j = 0; j < 26; j++){
            //loop through the alphabet
            if(messageText[i] == alpha[j]){
                //when a match is found, use the letters index to assign the cipher letter in the same index to the encrypted text.
                encryptedMessage[i] == cipherAlpha[j];
                //printf("%c ",messageText[i]);
                //printf("%c ",alpha[j]);
                //printf("%c\n",cipherAlpha[j]);
                //printf("%c \n",encryptedMessage[i]);
            }
            
        }

            
        }
    }

/*
    for(int i = 0; i < sizeof(encryptedMessage); i++){
        printf("%c",encryptedMessage[i]);
    }
*/

printf("\nI couldnt get it to work.\n");

}


//==============================================================================================================================================
//Message Decryption Program
void program2Decrypt(void){
    
    char alpha[26] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
    char cipherAlpha[26];
    
    printf("\nDecrypt a Message using a rotation cipher.\n");
    //printf("Feature Not Implimented - returning to main menu.\n");
    
    //decrypt "SJSFMPCRM WG O USBWIG. PIH WT MCI XIRUS O TWGV PM WHG OPWZWHM HC QZWAP O HFSS, WH KWZZ ZWJS WHG KVCZS ZWTS PSZWSJWBU HVOH WH WG GHIDWR. - OZPSFH SWBGHSWB"

    char encryptedMessage[] = "SJSFMPCRM WG O USBWIG. PIH WT MCI XIRUS O TWGV PM WHG OPWZWHM HC QZWAP O HFSS, WH KWZZ ZWJS WHG KVCZS ZWTS PSZWSJWBU HVOH WH WG GHIDWR. - OZPSFH SWBGHSWB"; 
    printf("the encrypted message:\n");
    printf("%s", encryptedMessage);
    int key;
   
    printf("Enter a Key: ");
    scanf("%d",&key);
    //Check that this number is positve
    while(key < 0){
        printf("Try again (use a positive number): ");
        scanf("%d",&key);
    }
   
/*    printf("BRUTE FORCE DECRYTION:");
    for(key = 0; key < 26; key++){    //loop through all itterations of the rotation based cipher alphabets
        printf("\n");
        printf("Key: %d -->",key);
*/    
        
        reorderAlpha(key,alpha,cipherAlpha);
        //printf("%s\n",cipherAlpha);

        printf("The Decrypted Message\n");

        for(int i = 0; i <= sizeof(encryptedMessage); i++){
        //loop through each letter in the encryptedMessage
            //find a match to the letter in the alphabet        
            for(int j = 0; j < 26; j++){
                //loop through the alphabet
                if(encryptedMessage[i] == alpha[j]){
                //when a match is found, use the letters index to assign the cipher letter in the same index to the encrypted text.
                encryptedMessage[i] == cipherAlpha[j];
                //printf("%c ",messageText[i]);
                //printf("%c ",alpha[j]);
                printf("%c",cipherAlpha[j]);
                //printf("%c \n",encryptedMessage[i]);
        }
        //}
    }
}

printf("\nI didnt get this too work.\n");

}
//==============================================================================================================================================
//Decode Message using a Dictionary
void program3Decode(void){
    printf("\nDecode an encrypted message using a dictionary attack.\n");
    printf("Feature Not Implimented - returning to main menu.\n");  
}  

//==============================================================================================================================================
//Exit Program - Housekeeping
void program4Exit(void){
    printf("\nProgram Closed\n");
    printf("Christopher Sawyer - C3181689\n\n\n");
}    

//==============================================================================================================================================
// String to Uppercase
//Input Args:
//Char String - An array of characters - the input message that needs to be converted to uppercase
void stringToUpper(char string[]){
   int index = 0;
   while (string[index] != '\0') {
      if (string[index] >= 'a' && string[index] <= 'z') {
          string[index] = string[index] - 32;
      }
      index++;
   }
}

//==============================================================================================================================================
//Reorders the Alphabet in respect to the key
//Input Args are:
//Int Key - the rotation cipher
//Char alpha - the Array holding the current alphabet
//Char newAlpha - the Array holding the New Alphabet, ordered in respect to the key
void reorderAlpha(int key,char inputString[],char outputString[]){
    // reorder method e(x) = (m + k)(mod 26)
    for(int i = 0; i < 26; i++){
            outputString[i] = inputString[((i + key) % 26)];
            //printf("%c.",outputString[i]);
    }
}