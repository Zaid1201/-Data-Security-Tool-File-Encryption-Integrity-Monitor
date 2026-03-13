# Data Security Tool – File Encryption & Integrity Monitor

## Overview
A Java-based graphical application that provides file and folder encryption capabilities using AES-256. The tool allows users to scan directories, view file metadata, encrypt/decrypt content, and maintain activity logs for auditability.

## Features
- **Directory Scanning**: Browse and select any directory to view its contents in an interactive tree structure
- **File/Folder Metadata Display**: View file path, name, type, size, timestamps, and permissions
- **AES-256 Encryption**: 
  - Single file encryption using built-in password
  - Folder encryption with user-defined passwords
  - File integrity verification using SHA-256 hashing
- **Decryption**: Restore encrypted files to original format with password verification for folders
- **Activity Logging**: All actions automatically saved to `filecrypt_log.txt`
- **User-Friendly GUI**: Built with Java Swing for intuitive navigation and real-time system feedback

## Technologies Used
- **Language**: Java (JDK 11 or newer)
- **GUI Framework**: Java Swing
- **Cryptography**: AES-256 (ECB mode), SHA-256 hashing
- **Libraries**: Built-in Java libraries only (no external dependencies)

## Installation & Setup

### Prerequisites
- Java Development Kit (JDK) 11 or newer
- Verify installation:
  ```bash
  java --version

### Running the Application

### Option 1: Using Executable

Simply run the provided .exe file.

### Option 2: From Terminal
#### Navigate to the directory containing EncryptionGUI.java
  ```bash
  cd path/to/project/directory
  ```
#### Compile the application
  ```bash
  javac EncryptionGUI.java
  ```

#### Run the application
  ```bash
  java EncryptionGUI
  ```

How to Use
----------

### 1\. Scanning a Directory

*   Click the **"Scan"** button
    
*   Browse and select the directory you want to scan
    
*   The directory contents will appear in the left-hand tree pane
    

### 2\. Viewing Metadata

*   Select any file or folder from the tree
    
*   Metadata (path, name, size, timestamps, permissions) displays in the right panel
    

### 3\. Encrypting Files/Folders

*   **For single files**: Select a file and click **"Encrypt"** (uses built-in password)
    
*   **For folders**: Select a folder and click **"Encrypt"**, then enter a unique password when prompted
    
*   Encrypted files receive the .enc extension
    

### 4\. Decrypting Files/Folders

*   Select an encrypted file (.enc) or folder and click **"Decrypt"**
    
*   For folders, enter the same password used during encryption
    

### 5\. Viewing Logs

*   Click **"View Logs"** to open the log window
    
*   Logs are automatically saved to filecrypt\_log.txt in the application directory
    

Encryption Mechanism
--------------------

1.  AES-256 bit key computed by applying SHA-256 hashing to the password
    
2.  SHA-256 hash of plaintext computed for integrity verification
    
3.  Encrypted file begins with 4-byte header "FENC" followed by the 32-byte plaintext hash
    
4.  AES-ECB applied to produce ciphertext
    
5.  Original file deleted and replaced with encrypted version (atomic operation)
