## Verifiable Refund Mechanism for Secure Transactions

A cryptographically secure transaction and refund system that integrates Ephemeral X25519, AES-GCM, and Ed25519 Digital Signatures to ensure confidentiality, integrity, authenticity, and forward secrecy throughout the transaction lifecycle.

## Project Overview

Refund mechanisms in financial systems are highly vulnerable to fraud, tampering, and forgery if not cryptographically bound to original transactions.
This project proposes and demonstrates a hybrid cryptographic framework that securely links transactions and refunds using modern cryptographic primitives.

The system:

Encrypts transaction and refund data

Authenticates users via digital signatures

Detects any tampering in real time

Demonstrates secure refund approval workflows

An interactive Streamlit web application is used to visualize transaction creation, refund requests, tamper simulation, and audit logs.

## Objectives

Design a secure transaction–refund mechanism

Integrate key exchange, encryption, and digital signatures

Prevent forged or altered refund requests

Detect tampering during transaction and refund stages

Demonstrate cryptographic guarantees through a live demo

## Technologies Used
Category	Tools
Programming Language	Python
Web Framework	Streamlit
Cryptography	AES-GCM, HKDF, Ed25519, X25519
Libraries	cryptography, PyNaCl
Environment	VS Code / Google Colab

## Cryptographic Algorithms

1️⃣ Ephemeral X25519 (Key Exchange)

Used to derive a shared secret between sender (Alice) and receiver (Bob)

Ensures forward secrecy by discarding ephemeral keys after use

2️⃣ AES-GCM (Authenticated Encryption)

Encrypts transaction and refund data

Provides confidentiality + integrity

Any ciphertext modification results in decryption failure

3️⃣ Ed25519 (Digital Signatures)

Authenticates transactions and refund requests

Prevents impersonation, forgery, and replay attacks

## Integrated Workflow
Transaction Creation

Alice generates an ephemeral X25519 key

AES key derived using HKDF

Transaction details encrypted with AES-GCM

Encrypted data signed using Ed25519

Bob verifies signature and decrypts transaction

Refund Process

Alice submits encrypted and signed refund request

Bob verifies authenticity and integrity

Bob approves refund by signing the decrypted request

Tamper Detection

Any change in ciphertext, signature, or transaction ID is detected

System immediately rejects forged or corrupted data

## To Run the Project
1️⃣ Install Dependencies
pip install streamlit cryptography pynacl

2️⃣ Run the Application
streamlit run secure_refund_demo_tamper.py

## Features Demonstrated

Secure transaction creation

Refund request verification

Tamper simulation (transaction & refund)

Audit logs of valid and tampered records

Real-time cryptographic verification

## Security Analysis

Confidentiality: Only intended recipients can decrypt data

Integrity: AES-GCM authentication tag detects any modification

Authenticity: Ed25519 signatures prevent forgery

Forward Secrecy: Ephemeral X25519 keys ensure past data remains secure

Tamper Resistance: Altered transactions and refunds are immediately rejected
