# py-encrypter

py-encrypter encryptes your python file or an entire directory and outputs a single .py file which stores n runs your encrypted files

# cmd line Arguments
-i (filepath)
[-d] (dirpath)
[-o] (output filepath)

# Usage
## encrypting a single file:
Run the python scripy with the file path as cmd line argument (-i)
eg: python3 encrypter.py -i path/to/your/file

## encrypting a directory
Run the python scripy with the directory path and the main file path (file to run first) as cmd line argument (-i)
eg:  python3 encrypter.py -d path/to/your/dir -i path/to/your/file

Just run the output file which cointains your encrypted source code to run your code

NOTE: if you want to decrypt your sourse code permanently add and option [-o] to your encrypted file or output file and it will create an output file in temp folder with your decrypted files
eg: python3 output.py -o
