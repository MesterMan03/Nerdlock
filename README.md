# Nerdlock - Simple E2EE messaging app

## Overview
Nerdlock is an E2EE messaging app running on Express and using MongoDB as a database.

The repository contains both the backend and the frontend which is served by the same Express application.

> **Warning**
> This is still pretty much in beta, which means a lot of features are missing, and security is also going to improve.

## Features
* Encrypted messages using AES256-GCM and ECDSA with P-521 for signatures and verification.
* Users share private data with each other using the X3DH protocol.
* TOTP 2FA.

## Installation
> **Note**
> You need to have at least Node v14 installed
1. Clone the repo with ```git clone https://github.com/MesterMan03/NerdLock.git``` and install the dependencies with ```npm install```.
2. After that you can compile the Typescript code with ```npm run build```.
3. Now you need to create a config file (you can find an example in the repository).
4. With all set you can start the server (which includes both backend and frontend) with ```npm start start <your config file>```.
