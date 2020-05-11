/*
*   @date           1 April, 2020
*   @author         Devang Manoj Sharma
*   @V#             V00931210
*   @version        1.0
*   @platformInfo   Tested on Ubuntu Budgie 18.04
*   @about          An implementation of Howard M. Hey's tutorial on differential cryptanalysis.
*/



#include<stdio.h>
#include<stdlib.h>
#include<math.h>

void addBorder(int);
void displayIP();
void displayOP();
void showSboxmapping();
void genDiffTab();
void genKey();
int permuteText(int);
int toBinary(int);
void encrypt(int);
void permuteBits();
int toDecimal();
int sBoxdOP(int);
void attackCipher();

//#define SHOWOP //uncomment this line for generating a detailed output corresponding to each of the plaintext pairs
#define SAMPLESPACE 100000
#define HEX 	    16
#define KEYSPACE    10
#define PAIR 	    2

int sBox[HEX]                   = {0xE,4,0xD,1,2,0xF,0xB,8,3,0xA,6,0xC,5,9,0,7};
int revSbox[HEX]                = {0xE,3,4,8,1,0xC,0xA,0xF,7,0xD,9,6,0xB,2,0,5};
int pBox[HEX]                   = {1,5,9,13,2,6,10,14,3,7,11,15,4,8,12,16};
short key[KEYSPACE]             = {0};
short plainText[PAIR]           = {0};
short cipherText_0[SAMPLESPACE] = {};
short cipherText_1[SAMPLESPACE] = {};
int xTwo[HEX][HEX]              = {0};
int delY[HEX][HEX]              = {0};
int bin[HEX]                    = {0};
int n1[HEX]                     = {0};
int decimal[4]                  = {0};

void attackCipher(){
    /*
    *   Uses the differential characteristics and the cipherText_0 and cipherText_1 pairs generated in encrypt() function to
    *   break the cipher 
    */
    int cIndex;
    int kCount;
    float keyCounter[256] = {0};
    int delU4 = 0x0606;
    int tu1, tu2, itu1, itu2;
    int flag = 1;
    printf("\n===============!!!Attack started on Toy Cipher!!!=================\n");  
    for(cIndex=0; cIndex<SAMPLESPACE; cIndex++){ //use all the ciphertext present in the samplespace
        tu1 = ((cipherText_0[cIndex] & 0XF000)>>12) ^ ((cipherText_0[cIndex] & 0xF0)>>4); //Checking whether first and third nibble are same
        tu2 = ((cipherText_1[cIndex] & 0XF000)>>12) ^ ((cipherText_1[cIndex] & 0xF0)>>4); //If they're same then tu1 and tu2 will be zero
        if((tu1^tu2) == 0){ //and the XOR of tu1 and tu2 will also be equal to zero ==> this is ciphertext pair we are looking for!! If !=0 then discard the cipherText pairs
            for(kCount=0; kCount<256; kCount++){ //Since they genKey() function only generates keys with value <= 128 ==> The max key value will be 2^8 = 256
                itu1 = revSbox[(((cipherText_0[cIndex] & 0XF00)>>4)^(kCount & 0xF0))>>4]; //256 =2 bytes, here we are XORing second nibble of cipher with second nibble of key
                tu1 = (itu1<<8) ^ (revSbox[(cipherText_0[cIndex] & 0xF)^(kCount & 0xF)]); //and passing it through the revSbox. Same is repeated for fourth nibble too for
                itu2 = revSbox[(((cipherText_1[cIndex] & 0XF00)>>4)^(kCount & 0xF0))>>4]; //both the cipherText. Finally the result is combined in to single 16 bit value
                tu2 = (itu2<<8) ^ (revSbox[(cipherText_1[cIndex] & 0xF)^(kCount & 0xF)]); //And this result XORed i.e equivalent to revSbox[C0 ^ key5] ^ revSbox[C1 ^ key5]
                if(delU4 == (tu1^tu2)){ //The result for above expression should be equal to deltaU4 which is 0x0606
                    keyCounter[kCount]++; // If result is equal to deltaU4 then increment the count for that key and repeat the process for all 256 keys
                } //Please note that 256 is considered because we only want to find the subkey which is 8 bit long OR a nibble each for K5,5 to K5,8 and K5,13 to K5,16
            }//kCount
        }//if tu1^tu2
    }//cIndex samplespace
	int probableKey = 0; //define an int variable which will store the value of probable key
	float maxCountVal = (keyCounter[1]/1000000); //get a reference value for comparision
    printf("\nCurrent max counted value for the key is:   %f, and keyCounter[1] is:   %f\n", maxCountVal, keyCounter[1]);
	for(kCount = 0; kCount < 256; kCount++){ //start iterating through each element of keyCounter[] array which is holding the key count
		if( kCount%5 == 0)
            printf("\n"); //prints next line after 5 counts are printed, for pretty printing
		if( maxCountVal < (keyCounter[kCount]/1000000)) //This is the logic for finding the key with the highest probability or count
		{
			maxCountVal = (keyCounter[kCount]/1000000); //swap maxCountVal with new one
			probableKey = kCount ; //corresponding index is the probable key
		}
		printf(" %02X| %f|",kCount, keyCounter[kCount]/1000000);      
	}
	printf("\n\nSubkey found is:\t%02X\n", probableKey);
    printf("\n===============!!!Attack completed on Toy Cipher!!!=================\n");  
}

int sBoxdOP(int input){
    /*
    *   Splits the input decimal value in to 4 nibbles and passes each nibble through sBox[16].
    */
    if(input<=0XF){
        decimal[3] = input&0XF; //seperates LSB
    }
    else if(input<=0xFF){
        decimal[3] = input&0xF;
        decimal[2] = (input>>8)&0xF;
    }
    else if(input<=0xFFF){
        decimal[3] = input&0xF;
        decimal[2] = (input>>4)&0xF;
        decimal[1] = (input>>8)&0xF;
    }
    else{
        decimal[3] = input&0xF;
        decimal[2] = (input>>4)&0xF;
        decimal[1] = (input>>8)&0xF;
        decimal[0] = (input>>12)&0xF; //seperates MSB
    }
    return ((sBox[decimal[0]]<<12)|(sBox[decimal[1]]<<8)|(sBox[decimal[2]]<<4)|(sBox[decimal[3]]));/*Passes each nibble through
                                                                                                     sBox, combine them and
                                                                                                     return a decimal equvalent                                                                                                     value*/
}

void permuteBits(){
    /*
    *   Permutes the binary representation obtained in toBinary() and saves the output in n1[16] global array
    */

    int i;
    for(i=0; i<16; i++){
        if(bin[i] == 1){ //check which bit is 1 and move it to respective position mentioned in pBox[16]
            n1[pBox[i]-1] = 1;  /*since bit numbering starts from 1 and array index starts from zero, one is substracted from 
                                  the permuation position*/
        }
    }
}


void encrypt(int count){
    /*
    *   Encrypts plaintext pairs present in plainText[0] and plainText[1] global arrays
    *   Generates corresponding ciphertext pairs and saves them in cipherText_0 and cipherText_1 global arrays
    *   Takes 'count' as a parameter for keeping the generated ciphertext pairs in sync
    */
    int i, j;
    int keyedVal; 
    int ldelU, ldelV;

    for(j=0; j<2; j++){
        ldelU = plainText[j];//start with plainText[0], assign it to local deltaU var
#ifdef SHOWOP
        printf("\nplainText[%d]: %d \n", j, plainText[j]);
#endif

        for(i=0; i<3; i++){ //run for loop for round 0 to round 2 since permutation is only included till 3 rounds
#ifdef SHOWOP
            printf("\n=> Round: %d and key is %d\n", i, ((key[i]<<8)^(key[2*i+1])));
#endif

            keyedVal = ((ldelU & 0xFF00)^(key[2*i]<<8))^((ldelU & 0xFF)^key[2*i+1]); //XORing key with ldelU "byte by byte", since generated key is "1 byte each"

#ifdef SHOWOP
            printf("\n\t- Value after XORing the key is: %d\n", keyedVal);
#endif

            ldelV = sBoxdOP(keyedVal); //split XORed key and ldelU in nibbles and pass it through s-box

#ifdef SHOWOP
            printf("\n\t- Value at the end of S-Box is:  %d\n", ldelV);
#endif

            ldelU = permuteText(ldelV); //permute ldelV and generate ldelU which will be used as an input for next round

#ifdef SHOWOP
            printf("\n\t- Permuted Value at the end of Round: %d is  %d\n",i, ldelU);
#endif
        }

#ifdef SHOWOP
        printf("\n=> Round: %d and key is %d\n", i, ((key[2*i]<<8)^(key[2*i+1]))); // i = 3 ==> round 4
#endif

        keyedVal = ((ldelU & 0xFF00)^(key[2*i]<<8))^((ldelU & 0xFF)^key[2*i+1]); //key mixing

#ifdef SHOWOP
        printf("\n\t- Value after XORing the key is: %d\n", keyedVal);
#endif

        ldelV = sBoxdOP(keyedVal); //split XORed key and ldelU and pass it through s-box

#ifdef SHOWOP
        printf("\n=> Value at the end of Round: %d is  %d\n",i, ldelV);
#endif

        //xor last round's ciphertext and the key
        keyedVal = ((ldelV & 0xFF00)^(key[8]<<8))^((ldelV & 0xFF)^key[9]);
        if(j==0)
            cipherText_0[count] = keyedVal;
        else
            cipherText_1[count] = keyedVal;

#ifdef SHOWOP
        printf("\n=> Value at the end of Round: 4 is  %d and key is: %d\n", keyedVal, ((key[8]<<8)^(key[9])));
        if(j==0)
            printf("\n===============!!!Encryption complete for first plaintext!!!==============\n");  
        else
            printf("\n===============!!!Encryption complete for second plaintext!!!==============\n\n");  
#endif
    }
}

int toBinary(int n){
    /*
    *   Takes a decimal number as an input and converts it to binary and saves it to bin[16] array which is global array.
    */
    int i, k;

    for (i = 15; i >= 0; i--){ 
        k = n >> i;
        if (k & 1){
            bin[15-i] = 1;
        } 
        else{
            bin[15-i] = 0;
        }
    }
}

int toDecimal(){
    /*
    *   Uses permuted array to represent binary value saved in n1[16] to decimal representation.
    *   Although this function can be used to generate decimal representation of any 16-bit binary number saved in an array.
    */
    int decimalU = 0; 
    int i;

    for(i=15; i>=0; --i){
        if (n1[15-i]==1){
            decimalU+= (1<<i); //simply left shift 1 wherever 1 is present in n1[16] array and add it to decimalU
        }
        n1[15-i] = 0; //reset n1[16] to 0, since it is global array, which is updated on the fly when permuteText() is called
    }
    return decimalU; //return decimal representation
}

int permuteText(int ldelV){
    /*
    *   Takes decimal input ldelV (<==> local deltaV) and converts it to binary and finally permutes the bits according to the
    *   bit position defined in pBox array defined on the start of this code. 
    */
    toBinary(ldelV);            //decimal plainText to binary in 16 bits
    permuteBits();              //permutes the binary value obtained from above function call
    int ldelU = toDecimal();    //converts permuted binary value to decimal
    return ldelU;               //returns ldelU which is equal to permuted version of ldelV
}

void showSboxmapping(){
    printf("\n===============!!!S-Box input and output mapping is shown below!!!===============\n");
    printf(" -");
    addBorder(43);

    displayIP();

    printf("|-");
    addBorder(43);
    printf("|");

    displayOP();

    printf(" -");
    addBorder(43);
    printf("\n");
}

void addBorder(int num){
    /*
    *   This function is used for adding border to the output of showSboxmapping() function. 
    */
    int i;
    for(i=0; i<num; i++){
        printf("--");
    }
}

void displayIP(){
    /*
    *   Pretty prints the input-mappings of showSboxmapping() 
    */
    int i;
    printf("\n|input\t| ");
    for(i=0; i<16; i++){
        printf("%X  | ", i);
    }
    printf("\n");
}

void displayOP(){
    /*
    *   Pretty prints the output-mappings of showSboxmapping() 
    */
    int i;
    printf("\n|output\t| ");
    for(i=0; i<16; i++){
        printf("%X  | ", sBox[i]);
    }
    printf("\n");
}

void genKey(){
    /*
    *   Generates 10 key pairs of 1 byte each which later will be used in key-mixing stage.
    *   Each consecutive pair corresponds to a complete key of 2 bytes OR 16 bits.
    */
    int i;
    for(i=0; i<10; i++){
        key[i] = rand() % 128;
    }
}

void genDiffTab(){
    /*
    *   I have created this function just for sake of convenience for generating differential table. Though we won't be using
    *   this anywhere in the encrypt() OR attackCipher() functions!!
    */
    printf("\nDisplaying XOR differential table:\n");

    int delX, xOne; 
    int row, col;

    for(delX = 0; delX < 16; delX++)
        for(xOne = 0; xOne < 16; xOne++)
            xTwo[delX][xOne] = delX^xOne; //generates X2 corresponding to all possible combination of deltaX and X1

    for(delX = 0; delX < 16; delX++)
    {
        for(xOne = 0; xOne < 16; xOne++)
            printf("  %d ", xTwo[delX][xOne]); //prints X2 corresponding to deltaX and X1
        printf("\n");
    }

    for(delX=0; delX<16; delX++)
        for(xOne=0; xOne<16; xOne++){
            row = xTwo[delX][xOne]^xOne;
            col = sBox[xTwo[delX][xOne]]^sBox[xOne];
            delY[row][col]++; //generates deltaY corresponding to deltaX = X1 xor X2
        }

    printf("\n");

    for(delX = 0; delX < 16; delX++)
    {
        for(xOne = 0; xOne < 16; xOne++)
            printf("  %d ", delY[delX][xOne]); //prints deltaY
        printf("\n");
    }
}

int main(){
    srand(time(NULL));  //seed the random function

    showSboxmapping();  //prints s-box mapping for input and output

    genDiffTab();       //prints differential table

    printf("\n");

    genKey();           //generates 10 set of key for each round(from 0 to 4!!)

    int count;
    for(count=0; count<SAMPLESPACE; count++){//loops runs for 'samplespace' # of times and finally creates pairs of c0 and c1
        plainText[0] = rand() % 65535; //rand() function is used to create random plaintext pairs which are in range 0 to FFFF
        plainText[1] = plainText[0] ^ 0x0B00; //using deltaP and P0 for creating P1
#ifdef SHOWOP
        printf("\n===============!!!Encryption started for PlainText pair!!!=================\n");  
#endif
        encrypt(count); //encrypts plainText pair P0 and P1 which is a global variable and saves c0 and c1 in global array var
    }

    printf("\nLast round key is:\t%02X  %02X\n", key[8], key[9]); //This is the key whose corresponding subkey we want to find

    attackCipher(); //Initiates the attack using the ciphertext pairs obtained in encrypt() function

    return 0;
}
