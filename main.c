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

int main(void){
    
    
    //ititalise the alphabet into an array
    char alpha[26] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
    
    //print all elements in the array
    for(int i = 0; i < 26; i++){
        printf("%c\n",alpha[i]);
    }    
    
    
    
  return 0;
}
