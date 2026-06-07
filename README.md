# Raster Steganography
A simple Windows application used to conceal a binary message (which can be a file of any type) within a PNG image (a process called **Encoding**). Another user can then use the app to extract that message from that image (a process called **Decoding**).

Compatible with **Windows Vista and higher**.

## `core.h` and `core.cpp`
These are the "module" that contains the core steganographic routines used to perform the Encoding and Decoding operations. This module is intended to be used not only within this application itself, but also by other developers keen on creating applications that require the functionality of image steganography.

## `shell.cpp`
This file defines the application's `wmain` function and handles interactions with the user. For example, in the case of an **Encode** operation, it will display three **Common File Dialogs** to take input from the user: one dialog to ask for **the carrier image file**, one to ask for **the message file**, and one to ask for the location in which **the resulting (modified) carrier image file** is to be stored. After the user specifies the carrier file and the message file within the dialogs, `shell.cpp` will pass these files to the core routines within `core.cpp` to perform the steganographic operation. `shell.cpp` will also **handle the output messages** (such as **displaying the percentage of progress** in the console window)
