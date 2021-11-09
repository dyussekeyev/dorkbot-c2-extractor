# dorkbot-c2-extractor

This repository contains a source code of the following scripts:
a) dorkbot_extract_dll.py - script that extracts DLL that embedded to the dropper
b) dorkbot_decrypt_strings.cpp - script that decrypts C2 domains from strings inside of embedded DLL

Scripts are developed for the sample mentioned in Checkpoint's blog (https://research.checkpoint.com/2018/dorkbot-an-investigation/).

The file 'strings_list_c2.txt' contains the decrypted list of C2 domains.
