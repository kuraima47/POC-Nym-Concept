#ifndef UNTITLED_CLASS_H
#define UNTITLED_CLASS_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <stdbool.h>

#define BUFFER_SIZE 4096
#define MAX_MESSAGES 1
#define MESSAGE_LENGTH 4096
#define PADDING RSA_PKCS1_PADDING
#define NUM_THREADS 4
#define MAX_MESSAGE_PARTS 100
#define MAX_MESSAGE_DATA 100

typedef struct {
    size_t taille;
    char content[MESSAGE_LENGTH];
} Message;

typedef struct {
    char * identifiant;
    char * ip;
    int port;
}Road;

typedef struct {
    RSA * all_key;
    Road * roads;
    Road * ownRoad;
    Message *messages;
    int message_count;
} Node;

typedef struct {
    Node* node;
    int port;
} ThreadArgs;

typedef struct {
    Road * road;
    char * message;
    Node * nodes;
} SendArgs;

typedef struct {
    int id;
    char* messageParts[MAX_MESSAGE_PARTS];
    int partsReceived;
    int totalParts;
} MessageData;

#endif //UNTITLED_CLASS_H
