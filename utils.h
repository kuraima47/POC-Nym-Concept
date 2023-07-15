#ifndef UNTITLED_UTILS_H
#define UNTITLED_UTILS_H
#include "class.h"

char* base64_encode(const unsigned char* buffer, size_t length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    char* base64_data = (char*)malloc((bufferPtr->length + 1) * sizeof(char));
    if (base64_data == NULL) {
        fprintf(stderr, "Failed to allocate memory for base64_data\n");
        return NULL;
    }
    memcpy(base64_data, bufferPtr->data, bufferPtr->length);
    base64_data[bufferPtr->length] = '\0';

    return base64_data;
}

unsigned char* base64_decode(const char* buffer, size_t* length) {
    BIO *bio, *b64;
    int decodeLen = (int)*length;
    unsigned char* decode = malloc(decodeLen + 1);
    if (decode == NULL) {
        fprintf(stderr, "Failed to allocate memory for decode\n");
        return NULL;
    }
    memset(decode, 0, decodeLen + 1);

    bio = BIO_new_mem_buf(buffer, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *length = BIO_read(bio, decode, decodeLen);

    BIO_free_all(bio);

    if (*length == 0) {
        free(decode);
        return NULL;
    }

    return decode;
}

Node* findNodeWithRoadID(Node* nodes, int nodeCount, char* roadID) {
    for (int i = 0; i < nodeCount; i++) {
        int roadCount = NUM_THREADS + 1;
        for (int j = 0; j < roadCount; j++) {
            if (strcmp(nodes[i].roads[j].identifiant, roadID) == 0) {
                return &nodes[i];
            }
        }
    }
    return NULL;
}

Road* findRoadWithID(Road* roads, int roadCount, char* roadID) {
    for (int i = 0; i < roadCount; i++) {
        if (strcmp(roads[i].identifiant, roadID) == 0) {
            return &roads[i];
        }
    }
    return NULL;
}

static int print_errors_cb(const char *str, size_t len, void *u) {
    return fputs(str, stderr);
}

void encrypt_aes(unsigned char * sym_key, unsigned char * iv, unsigned char * encrypted_data, int * encrypted_length, char * message) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, sym_key, iv)) {
        printf("Erreur lors de l'initialisation du chiffrement.\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (!EVP_EncryptUpdate(ctx, encrypted_data, encrypted_length, (unsigned char*)message, strlen(message))) {
        printf("Erreur lors du chiffrement.\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int tmp_length = 0;

    if (!EVP_EncryptFinal_ex(ctx, encrypted_data + *encrypted_length, &tmp_length)) {
        printf("Erreur lors de la finalisation du chiffrement.\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    *encrypted_length += tmp_length;

    EVP_CIPHER_CTX_free(ctx);
}

void decrypt_aes(unsigned char * sym_key, unsigned char * iv, unsigned char * decrypted_data, int encrypted_length, const unsigned char * message_crypted){
    int decrypted_length = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, sym_key, iv)) {
        printf("Erreur lors de l'initialisation du déchiffrement.\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if(!EVP_DecryptUpdate(ctx, decrypted_data, &decrypted_length, message_crypted, encrypted_length)) {
        printf("Erreur lors du déchiffrement.\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int tmp_length;
    if(!EVP_DecryptFinal_ex(ctx, decrypted_data + decrypted_length, &tmp_length)) {
        ERR_print_errors_cb(print_errors_cb, NULL);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    decrypted_length += tmp_length;

    EVP_CIPHER_CTX_free(ctx);
}

int generate_random_len() {
    //srand(time(NULL));
    //int len = (rand() % (MAX_ROUTES - NUM_THREADS + 1)) + NUM_THREADS;
    return 4;
}

int envoyer_message(char *adresse_serveur, int port_serveur, Message *message) {

    WSADATA wsa;
    SOCKET socket_desc;
    struct sockaddr_in serveur;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Erreur d'initialisation de Winsock : %d", WSAGetLastError());
        return 0;
    }

    socket_desc = socket(AF_INET, SOCK_STREAM, 0);

    if (socket_desc == INVALID_SOCKET) {
        printf("Impossible de créer le socket : %d", WSAGetLastError());
        WSACleanup();
        return 0;
    }

    serveur.sin_addr.s_addr = inet_addr(adresse_serveur);
    serveur.sin_family = AF_INET;
    serveur.sin_port = htons(port_serveur);

    if (connect(socket_desc, (struct sockaddr *)&serveur, sizeof(serveur)) == SOCKET_ERROR) {
        printf("Connexion échouée : %d", WSAGetLastError());
        closesocket(socket_desc);
        WSACleanup();
        return 0;
    }

    char message_string[MESSAGE_LENGTH];
    sprintf(message_string, "%s", message->content);
    if (send(socket_desc, message_string, (int)strlen(message_string), 0) == SOCKET_ERROR) {
        printf("Envoi echouer : %d\n", WSAGetLastError());
        closesocket(socket_desc);
        WSACleanup();
        return 0;
    }

    closesocket(socket_desc);
    WSACleanup();
    return 1;
}

int recevoir_message(int port_serveur) {
    WSADATA wsa;
    SOCKET socket_desc = INVALID_SOCKET, client_socket = INVALID_SOCKET;
    struct sockaddr_in serveur, client;
    int client_size;
    char buffer[BUFFER_SIZE];

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Erreur d'initialisation de Winsock : %d", WSAGetLastError());
        return 0;
    }

    socket_desc = socket(AF_INET, SOCK_STREAM, 0);

    if (socket_desc == INVALID_SOCKET) {
        printf("Impossible de créer le socket : %d", WSAGetLastError());
        WSACleanup();
        return 0;
    }

    serveur.sin_addr.s_addr = INADDR_ANY;
    serveur.sin_family = AF_INET;
    serveur.sin_port = htons(port_serveur);

    if (bind(socket_desc, (struct sockaddr *)&serveur, sizeof(serveur)) == SOCKET_ERROR) {
        printf("Erreur de liaison : %d", WSAGetLastError());
        closesocket(socket_desc);
        WSACleanup();
        return 0;
    }

    if (listen(socket_desc, SOMAXCONN) == SOCKET_ERROR) {
        printf("Écoute échouée : %d", WSAGetLastError());
        closesocket(socket_desc);
        WSACleanup();
        return 0;
    }

    printf("En attente de connexions...\n");

    client_size = sizeof(struct sockaddr_in);

    MessageData* messageDataArray[MAX_MESSAGE_DATA];
    int messageDataCount = 0;

    while ((client_socket = accept(socket_desc, (struct sockaddr *) &client, &client_size)) != INVALID_SOCKET) {

        int recv_size;
        memset(buffer, 0, BUFFER_SIZE);
        recv_size = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);

        if (recv_size == SOCKET_ERROR) {
            printf("Réception échouée : %d", WSAGetLastError());
            closesocket(client_socket);
            closesocket(socket_desc);
            WSACleanup();
            return 0;
        }

        buffer[recv_size] = '\0';
        char* decoded_buffer = NULL;
        char* decoded_message = NULL;
        size_t length_message = strlen(buffer);
        decoded_buffer = (char*)base64_decode(buffer, &length_message);
        size_t length_decoded = strlen(decoded_buffer);
        decoded_message = (char*) base64_decode(decoded_buffer, &length_decoded);

        int id, pos, len;
        char* infos = strstr(decoded_message, "^id^");
        char* id_pos;
        char* message;
        if (infos != NULL) {
            id_pos = infos + 4;
            int length = infos - decoded_message;
            message = malloc(length + 1);
            if (message == NULL) {
                printf("Error: memory allocation failed.\n");
                free(decoded_message);
                closesocket(client_socket);
                continue;
            }
            memcpy(message, decoded_message, length);
            message[length] = '\0';
        } else {
            printf("Error: id not found in buffer.\n");
            free(decoded_message);
            closesocket(client_socket);
            continue;
        }

        char* infos_id = strstr(id_pos, "$pos$");
        char* id_str;
        char* pos_len;
        if (infos_id != NULL) {
            pos_len = infos_id + 5;
            int length = infos_id - id_pos;
            id_str = malloc(length + 1);
            if (id_str == NULL) {
                printf("Error: memory allocation failed.\n");
                free(id_pos);
                closesocket(client_socket);
                continue;
            }
            memcpy(id_str, id_pos, length);
            id_str[length] = '\0';
        } else {
            printf("Error: pos not found in buffer.\n");
            free(id_pos);
            closesocket(client_socket);
            continue;
        }

        char* infos_len = strstr(pos_len, ">len>");
        char* len_str;
        char* pos_str;
        if (infos_len != NULL) {
            len_str = infos_len + 5;
            int length = infos_len - pos_len;
            pos_str = malloc(length + 1);
            if (pos_str == NULL) {
                printf("Error: memory allocation failed.\n");
                free(pos_len);
                closesocket(client_socket);
                continue;
            }
            memcpy(pos_str, pos_len, length);
            pos_str[length] = '\0';
        } else {
            printf("Error: len not found in buffer.\n");
            free(pos_len);
            closesocket(client_socket);
            continue;
        }

        len = strtol(len_str, NULL, 10);
        pos = strtol(pos_str, NULL, 10);
        id = strtol(id_str, NULL, 10);

        //printf("message : %s, id : %d, pos : %d, len : %d\n", message, id, pos, len);

        MessageData* md = NULL;
        for (int i = 0; i < messageDataCount; i++) {
            if (messageDataArray[i]->id == id) {
                md = messageDataArray[i];
                break;
            }
        }
        if (md == NULL) {
            md = malloc(sizeof(MessageData));
            md->id = id;
            md->partsReceived = 0;
            md->totalParts = 0;
            messageDataArray[messageDataCount++] = md;
        }

        md->messageParts[pos] = message;
        md->partsReceived++;

        if (md->totalParts < len) {
            md->totalParts = len;
        }

        if (md->partsReceived == md->totalParts) {
            printf("Message complet recu pour l'ID %d: ", id);
            for (int i = 0; i < md->totalParts; i++) {
                printf("%s ", md->messageParts[i]);
                free(md->messageParts[i]);
            }
            printf("\n");
            md->partsReceived = 0;
            md->totalParts = -1;
        }

        closesocket(client_socket);

    }

    if (client_socket == INVALID_SOCKET) {
        printf("Échec de l'acceptation de la connexion : %d", WSAGetLastError());
        closesocket(socket_desc);
        WSACleanup();
        return 0;
    }

    closesocket(socket_desc);
    WSACleanup();
    return 1;
}

void shuffle_messages(Node* node) {
    srand(time(NULL));
    for (int i = node->message_count - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        Message temp = node->messages[i];
        node->messages[i] = node->messages[j];
        node->messages[j] = temp;
    }
}

DWORD WINAPI receive_thread(LPVOID lpParam) {
    if (lpParam == NULL) {
        printf("lpParam is NULL.\n");
        return 1;
    }

    int port = *((int*) lpParam);
    int response = recevoir_message(port);
    if (response != 1){
        printf("error for receive message");
    }
    return 0;
}

DWORD WINAPI send_thread(LPVOID lpParam) {
    sleep(2);
    SendArgs* args = (SendArgs*) lpParam;
    Road * road = args->road;
    Node* nodes = args->nodes;
    char message[MESSAGE_LENGTH + 1];
    memcpy(message, args->message, strlen(args->message) + 1);

    printf("Envoie du message : %s \n", message);
    char temp[MESSAGE_LENGTH + 1];
    memset(temp, '\0', sizeof(temp));
    snprintf(temp, sizeof(temp), "%s-rod-%s", message, road->identifiant);
    memset(message, '\0', sizeof(message));
    strncpy(message, temp, sizeof(temp) - 1);
    message[sizeof(message) - 1] = '\0';

    int num_routes = generate_random_len();
    int indexs[num_routes];

    for (int i = 0; i < num_routes; i++){

        int index = rand() % NUM_THREADS;
        if((sizeof(indexs) / sizeof(int) == 0)||(indexs[i-1] != index)){
            indexs[i] = index;
        }else{
            while(indexs[i-1] == index){
                index = rand() % NUM_THREADS;
            }
            indexs[i] = index;
        }

        unsigned char sym_key[32];
        RAND_bytes(sym_key, sizeof(sym_key));

        unsigned char iv[AES_BLOCK_SIZE];
        RAND_bytes(iv, sizeof(iv));

        unsigned char encrypted_data[MESSAGE_LENGTH];
        int encrypted_length = 0;

        encrypt_aes(sym_key, iv, encrypted_data, &encrypted_length, message);

        unsigned char encrypted_key[MESSAGE_LENGTH];
        int encrypted_key_length = RSA_public_encrypt(sizeof(sym_key), sym_key, encrypted_key, nodes[index].all_key, PADDING);
        if(encrypted_key_length == -1) {
            printf("Erreur lors du chiffrement de la clé symétrique");
        }

        char* base64_key = base64_encode(encrypted_key, encrypted_key_length);
        char* base64_data = base64_encode(encrypted_data, encrypted_length);
        char* base64_iv = base64_encode(iv, sizeof(iv));

        memset(temp, '\0', sizeof(temp));

        snprintf(temp, sizeof(temp), "%s^key^%s>iv>%s$len$%d^len^%d-rod-%s", base64_data, base64_key, base64_iv, encrypted_length, encrypted_key_length, nodes[index].ownRoad->identifiant);
        memset(message, '\0', sizeof(message));
        strncpy(message, temp, sizeof(temp) - 1);
        message[sizeof(message) - 1] = '\0';
        /*free(base64_key);
        free(base64_data);
        free(base64_iv);*/
    }
    char* messageToSend = strstr(message, "-rod-");
    char* id;
    char* message_content;
    if (messageToSend != NULL) {
        id = messageToSend + 5;
        int length = messageToSend - message;
        message_content = malloc(length + 1);
        if (message_content != NULL) {
            memcpy(message_content, message, length);
            message_content[length] = '\0';
        }
    }
    char id_first_char[2];
    id_first_char[0] = id[0];
    id_first_char[1] = '\0';
    Node* node = findNodeWithRoadID(nodes, NUM_THREADS, id_first_char);
    if (node == NULL) {
        printf("Did not find a node with a road having the ID '%s'\n", id_first_char);
    }

    char *ip_str = node->ownRoad->ip;
    int port_send = node->ownRoad->port;
    char* base64_message = base64_encode(message_content, strlen(message_content));

    Message mess;
    strcpy(mess.content, base64_message);
    mess.taille = strlen(base64_message);
    int response = envoyer_message(ip_str, port_send, &mess);

    if(response == 1){
        printf("Message send to node %s correctly\n", id_first_char);
    }

    /*free(base64_message);
    free(message_content);
    free(ip);
    free(message);*/
    return 0;
}

DWORD WINAPI global_thread (LPVOID lpParam){
    sleep(2);
    SendArgs* args = (SendArgs*) lpParam;
    Road * road = args->road;

    Node* nodes = args->nodes;
    int id = 1;
    while(1){
        char message[MESSAGE_LENGTH] = {0};
        const char s[2] = " ";
        char* token;
        char temp[100];
        int pos = 0;
        int len = 0;

        printf("Enter le message : ");
        fgets(message, sizeof(message), stdin);
        message[strcspn(message, "\n")] = '\0';

        strcpy(temp, message);

        token = strtok(temp, s);
        while (token != NULL) {
            len++;
            token = strtok(NULL, s);
        }
        HANDLE threads[len];
        char temp2[strlen(message)+1];
        strcpy(temp2, message);
        char *saveptr;
        token = strtok_r(temp2, s, &saveptr);

        while (token != NULL) {
            char *formattedMessage = malloc(MESSAGE_LENGTH * sizeof(char));
            if (formattedMessage == NULL) {
                printf("Failed to allocate memory for formattedMessage\n");
                return -1;
            }

            sprintf(formattedMessage, "%s^id^%d$pos$%d>len>%d", token, id, pos, len);
            char * base64_formatted_message = base64_encode(formattedMessage, strlen(formattedMessage));
            free(formattedMessage);

            SendArgs* sendArgs = malloc(sizeof(SendArgs));
            if (sendArgs == NULL) {
                printf("Failed to allocate memory for sendArgs\n");
                return -1;
            }

            sendArgs->road = road;
            sendArgs->message = base64_formatted_message;
            sendArgs->nodes = nodes;

            HANDLE sendThread = CreateThread(NULL, 0, send_thread, sendArgs, 0, NULL);
            threads[pos] = sendThread;

            token = strtok_r(NULL, s, &saveptr);
            pos++;
        }
        WaitForMultipleObjects(len, threads, TRUE, INFINITE);
        id++;
    }
};

#endif //UNTITLED_UTILS_H
