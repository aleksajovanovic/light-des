------What Has Been Implemented------
1. ECB encryption and decryption
2. CBC encryption and decryption
3. CTR encryption and decryption

------------General Usage------------
Usage: crypt-keeper [--mode] [--enc/--dec] [--hex/--file] [int rounds] [decimal key] [plaintext/file name]

--mode: choose [--ECB/--CTR/--CBC]. With CTR and CBC mode you will be prompted whether or not you would like
        to use a fixed IV or a nonce. If the nonce option is chosen, the nonce will be printed to the screen 
        once it is generated so that you can use it during the decryption. For decryption, the nonce is to be 
        entered in decimal format.

--enc/--dec: choose whether you are decrypting or encrypting.

--hex/--file: if you use stdin, it is recommended you use the --hex flag and input hexidecimal values. For
              example, the command `crypt-keeper --CBC --enc --hex 1 455 ffffff` will treat `ffffff` as three
              bytes consisting of the binary values 11111111 11111111 11111111. To read from a file use the
              --file flag.

[int rounds]: number of rounds.

[decimal key]: key ranging from 0-511.

[plaintext/file name]: hexidecimal input from stdin or a file to be streamed from.

-------------Additional-------------
The program prints all output to stdout in hexidecimal format. So after any encryption, to decrypt you must copy
the output and decrypt it using the --dec and --hex flags. For convenience, we have provide a test file for 
encryption and decryption called test.txt.
