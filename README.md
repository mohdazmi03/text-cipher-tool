# Text Cipher Tool

A user-friendly desktop application built with Python and Tkinter for encrypting and decrypting text using classic ciphers.


## Description

This tool provides a simple graphical user interface (GUI) to perform basic text transformations using three different classical cipher methods:

1.  **Caesar Cipher:** A simple substitution cipher where each letter is shifted a fixed number of positions down the alphabet.
2.  **Vigenère Cipher:** A polyalphabetic substitution cipher that uses a keyword to determine the variable shift for each letter.
3.  **Keyed Columnar Transposition:** A transposition cipher that rearranges the letters of the plaintext based on the alphabetical order of a keyword.

The application allows users to easily switch between ciphers, enter the required key (shift number or keyword), input their text, and see the encrypted or decrypted result instantly.

## Features

*   **Graphical User Interface:** Easy-to-use interface built with Tkinter.
*   **Multiple Ciphers:** Supports Caesar, Vigenère, and Keyed Columnar Transposition.
*   **Encryption & Decryption:** Performs both plaintext-to-ciphertext and ciphertext-to-plaintext operations.
*   **Dynamic Key Input:** Shows the appropriate key input field (shift number or keyword) based on the selected cipher.
*   **Input Validation:** Checks for missing text or keys and provides user-friendly error messages.
*   **Scrollable Text Areas:** Handles larger blocks of text effectively.
*   **Cross-Platform (potential):** Should run on Windows, macOS, and Linux if Python and Tkinter are installed.

## Requirements

*   **Python 3.x:** The script is written in Python 3.
*   **Tkinter:** This is usually included with standard Python installations. However, on some Linux distributions, you might need to install it separately:
    ```bash
    # Debian/Ubuntu based systems
    sudo apt-get update
    sudo apt-get install python3-tk

    # Fedora based systems
    sudo dnf install python3-tkinter
    ```

## Installation and Running

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/mohdazmi03/text-cipher-tool.git
    ```
    *(Replace `mohdazmi03` if your username is different)*

2.  **Navigate to the directory:**
    ```bash
    cd text-cipher-tool
    ```

3.  **Run the script:**
    ```bash
    python cipher_tool.py
    ```
    *(Make sure your Python script file is named `cipher_tool.py` or update the command accordingly)*

## How to Use

1.  Run the `cipher_tool.py` script using Python.
2.  The application window will appear.
3.  **Enter Text:** Type or paste the text you want to encrypt or decrypt into the "Input Text" area.
4.  **Select Cipher:** Choose the desired cipher method (Caesar, Vigenère, or Transposition) using the radio buttons.
5.  **Enter Key:**
    *   If **Caesar** is selected, enter an integer shift value in the "Shift Key" field.
    *   If **Vigenère** or **Transposition** is selected, enter a keyword (letters only recommended) in the "Keyword" field. The label will update accordingly.
6.  **Process:**
    *   Click the **Encrypt** button to convert plaintext to ciphertext.
    *   Click the **Decrypt** button to convert ciphertext back to plaintext (using the same key and cipher type).
7.  **View Output:** The result will appear in the read-only "Output Result" area.
8.  Error messages will pop up if required input (text or key) is missing or invalid.

## Limitations

*   **Classic Ciphers Only:** These ciphers are **not secure** for modern cryptographic purposes and are primarily for educational or recreational use.
*   **Character Handling:**
    *   Caesar and Vigenère ciphers primarily process alphabetic characters (A-Z, a-z) and leave other characters (numbers, symbols, spaces) unchanged. Case is preserved in the output text but ignored in the Vigenère keyword.
    *   Transposition rearranges *all* characters in the input text.
*   **Padding:** The Transposition cipher uses a simple 'X' character for padding. This might cause issues if the original message ends with 'X'. Decryption simply removes trailing 'X's based on calculated padding length, which might be incorrect if 'X' was part of the original message.
*   **Keyword Cleaning:** Keywords for Vigenère and Transposition are automatically cleaned to contain only letters (A-Z, a-z).
