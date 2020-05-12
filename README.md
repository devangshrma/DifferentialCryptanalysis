# DifferentialCryptanalysis
This project was developed as a part of ECE 519C course work
*   **@date**           2 April, 2020
*   **@author**         Devang
*   **@version**        1.0
*   **@platformInfo**   Tested on Ubuntu Budgie 18.04
*   **@about**          An implementation of Howard M. Hey's tutorial on differential cryptanalysis.

Steps to run this code:-the
1) Compile the code using command:- gcc diffCryptAna.c -o diffCryptAna
(Note:- Ignore the warnings generated after running the above command)

2) Above step will result in to a generation of file name "diffCryptAna" which consists of binary. 

3) Run the generated binary **diffCryptAna** using the command "./diffCryptAna"

4) For more verbose output please uncomment line# 30 from the source code and re-compile the code. Incase you have decided to take a look at verbose output, then please redirect the output to some file which will make it easier to read the output. 
    -- For example:- ./diffCryptAna > op.txt
