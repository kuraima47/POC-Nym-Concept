#ifndef UNTITLED_NODE_H
#define UNTITLED_NODE_H
#include "utils.h"

Node* create_node(RSA * all_key, int port,char * ip,char * id, Road* roads) {
    Node* node = malloc(sizeof(Node));
    node->all_key = all_key;
    node->roads = roads;
    Road* road = malloc(sizeof(Road));
    road->identifiant = strdup(id);
    road->ip = ip;
    road->port = port;
    node->ownRoad = road;
    node->messages = malloc(sizeof(Message) * MAX_MESSAGES);
    node->message_count = 0;
    return node;
}

void free_node(Node* node) {
    //free(node->messages);
    //free(node);
}

void resend_messages(Node * node){
    for (int i = node->message_count - 1; i >= 0; i--) {
        char* messageToSend = strstr(node->messages[i].content, "-rod-");
        char* id;
        char* message_content = NULL;
        if (messageToSend != NULL) {
            id = messageToSend + 5;
            int length = messageToSend - node->messages[i].content;
            message_content = malloc(length + 1);
            if (message_content != NULL) {
                memcpy(message_content, node->messages[i].content, length);
                message_content[length] = '\0';
            }
        }
        char id_first_char[2];
        id_first_char[0] = id[0];
        id_first_char[1] = '\0';
        Road* road = findRoadWithID(node->roads, NUM_THREADS+1, id_first_char);
        if (road == NULL) {
            printf("Did not find a road with the ID '%s'\n", id_first_char);
            if (message_content != NULL) {
                free(message_content);
            }
            continue;
        }
        char *ip_str = road->ip;
        int port_send = road->port;
        char* base64_message = base64_encode(message_content, strlen(message_content));
        Message mess;
        strcpy(mess.content, base64_message);
        mess.taille = strlen(base64_message);
        int response = envoyer_message(ip_str, port_send, &mess);

        if(response == 1){
            printf("Message send to node %s correctly\n", id_first_char);
        }

        /*if (message_content != NULL) {
            free(message_content);
        }*/
    }
    node->message_count = 0;
}


DWORD WINAPI server_thread(LPVOID lpParam) {

    ThreadArgs *args = (ThreadArgs *) lpParam;
    Node *node = args->node;
    int port = args->port;
    WSADATA wsaData;
    SOCKET ListenSocket = INVALID_SOCKET, ClientSocket = INVALID_SOCKET;
    struct sockaddr_in server, client;
    int addr_len;
    char buffer[MESSAGE_LENGTH + 1];
    char decoded_buffer[MESSAGE_LENGTH + 1];
    char* message_crypted = NULL;
    char* key_str = NULL;
    char* iv = NULL;
    char* encrypted_len = NULL;
    unsigned char* decoded_enc = NULL;
    unsigned char* decoded_iv = NULL;
    unsigned char* decoded_key = NULL;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("Failed. Error Code : %d", WSAGetLastError());
        return 1;
    }

    if ((ListenSocket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Could not create socket : %d", WSAGetLastError());
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(port);

    if (bind(ListenSocket, (struct sockaddr *) &server, sizeof(server)) == SOCKET_ERROR) {
        printf("Bind failed with error code : %d", WSAGetLastError());
    }

    puts("Bind done");

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
        printf("Failed to get hostname: %d\n", WSAGetLastError());
        return 1;
    }

    struct hostent *host = gethostbyname(hostname);
    if (host == NULL) {
        printf("Failed to get host information: %d\n", WSAGetLastError());
        return 1;
    }
    char *ip_address;
    for (int i = 0; host->h_addr_list[i] != 0; ++i) {
        struct in_addr addr;
        memcpy(&addr, host->h_addr_list[i], sizeof(struct in_addr));
        char* ip_search = inet_ntoa(addr);
        if (strncmp(ip_search, "192.168", 7) == 0) {
            ip_address = ip_search;
        }
    }

    printf("Server listening on IP: %s, port: %d\n", ip_address, port);

    listen(ListenSocket, 3);

    addr_len = sizeof(struct sockaddr_in);

    while ((ClientSocket = accept(ListenSocket, (struct sockaddr *) &client, &addr_len)) != INVALID_SOCKET) {
        puts("Connection accepted");
        int bytes_received = recv(ClientSocket, buffer, MESSAGE_LENGTH, 0);
        if (bytes_received == SOCKET_ERROR) {
            printf("Erreur lors de la réception du message : %d\n", WSAGetLastError());
            closesocket(ClientSocket);
            continue;
        } else {

            if(bytes_received > MESSAGE_LENGTH){
                printf("avec la taille du message : %d\n", WSAGetLastError());
                closesocket(ClientSocket);
                continue;
            }
            buffer[bytes_received] = '\0';
            size_t length_message = strlen(buffer);
            strcpy(decoded_buffer,(char*)base64_decode(buffer, &length_message));

            char* infos = strstr(decoded_buffer, "^key^");
            char* key_iv;
            if (infos != NULL) {
                key_iv = infos + 5;
                int length = infos - decoded_buffer;
                message_crypted = malloc(length + 1);
                if (message_crypted == NULL) {
                    printf("Error: memory allocation failed.\n");
                    free(decoded_buffer);
                    closesocket(ClientSocket);
                    continue;
                }
                memcpy(message_crypted, decoded_buffer, length);
                message_crypted[length] = '\0';
            } else {
                printf("Error: key not found in buffer.\n");
                free(decoded_buffer);
                closesocket(ClientSocket);
                continue;
            }
            char* getiv = strstr(key_iv, ">iv>");
            char* iv_str;
            if (getiv != NULL) {
                iv_str = getiv + 4;
                int length = getiv - key_iv;
                key_str = malloc(length + 1);
                if (key_str == NULL) {
                    printf("Error: memory allocation failed.\n");
                    free(message_crypted);
                    free(decoded_buffer);
                    closesocket(ClientSocket);
                    continue;
                }
                memcpy(key_str, key_iv, length);
                key_str[length] = '\0';
            } else {
                printf("Error: >iv> not found in key_iv.\n");
                free(message_crypted);
                free(decoded_buffer);
                closesocket(ClientSocket);
                continue;
            }
            char* iv_start = strstr(iv_str, "$len$");
            char* len_str;
            if (iv_start != NULL) {
                len_str = iv_start + 5;
                int length = iv_start - iv_str;
                iv = malloc(length + 1);
                if (iv == NULL) {
                    printf("Error: memory allocation failed.\n");
                    free(key_str);
                    free(message_crypted);
                    free(decoded_buffer);
                    closesocket(ClientSocket);
                    continue;
                }
                memcpy(iv, iv_str, length);
                iv[length] = '\0';
            } else {
                printf("Error: $len$ not found in iv_str.\n");
                free(key_str);
                free(message_crypted);
                free(decoded_buffer);
                closesocket(ClientSocket);
                continue;
            }
            char* len_start = strstr(len_str, "^len^");
            char* len_key_str;
            if (len_start != NULL) {
                len_key_str = len_start + 5;
                int length = len_start - len_str;
                encrypted_len = malloc(length + 1);
                if (encrypted_len == NULL) {
                    printf("Error: memory allocation failed.\n");
                    free(iv);
                    free(key_str);
                    free(message_crypted);
                    free(decoded_buffer);
                    closesocket(ClientSocket);
                    continue;
                }
                strncpy(encrypted_len, len_str, length);
                encrypted_len[length] = '\0';
            } else {
                printf("Error: ^len^ not found in len_str.\n");
                free(iv);
                free(key_str);
                free(message_crypted);
                free(decoded_buffer);
                closesocket(ClientSocket);
                continue;
            }
            if (len_start != NULL) {
                size_t length_encr = strlen(message_crypted);
                size_t length_iv = strlen(iv);
                size_t length_key = strlen(key_str);
                decoded_enc = base64_decode(message_crypted, &length_encr);
                decoded_iv = base64_decode(iv, &length_iv);
                decoded_key = base64_decode(key_str, &length_key);
            }
            unsigned char dec_key[32];
            int encrypted_key_length = strtol(len_key_str, NULL, 10);
            int decrypted_key_length = RSA_private_decrypt(encrypted_key_length, decoded_key, dec_key, node->all_key, PADDING);
            if(decrypted_key_length == -1) {
                printf("Private Decrypt failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
                goto cleanup;
            }
            unsigned char decrypted_data[MESSAGE_LENGTH];
            int encrypted_length = strtol(encrypted_len, NULL, 10);
            decrypt_aes(dec_key, decoded_iv, decrypted_data, encrypted_length, decoded_enc);

            printf("decrypted_data = %s\n",decrypted_data);

            Message mess;
            strncpy(mess.content, (char *)decrypted_data, sizeof(mess.content) - 1);
            mess.content[sizeof(mess.content) - 1] = '\0';
            mess.taille = strlen((char *)decrypted_data);
            node->messages[node->message_count] = mess;
            node->message_count += 1;
            if(node->message_count == MAX_MESSAGES){
                shuffle_messages(node);
                resend_messages(node);
            }
            cleanup:
                /*if (decoded_buffer != NULL) {
                    free(decoded_buffer);
                    decoded_buffer = NULL;
                }
                if (message_crypted != NULL) {
                    free(message_crypted);
                    message_crypted = NULL;
                }
                if (key_str != NULL) {
                    free(key_str);
                    key_str = NULL;
                }
                if (iv != NULL) {
                    free(iv);
                    iv = NULL;
                }
                if (encrypted_len != NULL) {
                    free(encrypted_len);
                    encrypted_len = NULL;
                }
                if (decoded_enc != NULL) {
                    free(decoded_enc);
                    decoded_enc = NULL;
                }
                if (decoded_iv != NULL) {
                    free(decoded_iv);
                    decoded_iv = NULL;
                }
                if (decoded_key != NULL) {
                    free(decoded_key);
                    decoded_key = NULL;
                }*/
                closesocket(ClientSocket);
        }
    }
}

#endif //UNTITLED_NODE_H