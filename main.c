#include "node.h"

int main() {

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", GetLastError());
        return 1;
    }

    char ac[80];
    if (gethostname(ac, sizeof(ac)) == SOCKET_ERROR) {
        printf("Error when getting local host name\n");
        return 1;
    }

    struct hostent *phe = gethostbyname(ac);
    if (phe == 0) {
        printf("Error when getting host info\n");
        return 1;
    }
    char * ip;
    for (int i = 0; phe->h_addr_list[i] != 0; ++i) {
        struct in_addr addr;
        memcpy(&addr, phe->h_addr_list[i], sizeof(struct in_addr));
        char* ip_search = inet_ntoa(addr);
        if (strncmp(ip_search, "192.168", 7) == 0) {
            ip = ip_search;
        }
    }

    int port = 8089;


    HANDLE threads[NUM_THREADS+2];
    Road roads[NUM_THREADS+1];
    int ports[NUM_THREADS] = {8080, 8081, 8084, 8083};
    char * Ids[NUM_THREADS] = {"B", "C", "D", "E"};

    Node *nodes = malloc(NUM_THREADS * sizeof(Node));
    if (nodes == NULL) {
        printf("Memory allocation for nodes failed\n");
        return -1;
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        roads[i].identifiant = malloc(2 * sizeof(char));
        roads[i].identifiant[0] = *Ids[i];
        roads[i].identifiant[1] = '\0';
        roads[i].ip = ip;
        roads[i].port = ports[i];
    }
    HANDLE receiveThread = CreateThread(NULL, 0, receive_thread, &port, 0, NULL);
    threads[NUM_THREADS] = receiveThread;

    Road road;
    road.identifiant = malloc(2 * sizeof(char));
    road.identifiant[0] = 'F';
    road.identifiant[1] = '\0';
    road.ip = ip;
    road.port = port;

    roads[NUM_THREADS] = road;

    for (int i = 0; i < NUM_THREADS; i++) {
        RSA* rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
        if (rsa == NULL) {
            printf("Erreur lors de la génération de la clé RSA\n");
            for (int j = 0; j < i; j++) {
                free_node(&nodes[j]);
            }
            free(nodes);
            return -1;
        }
        nodes[i] = *create_node(rsa, ports[i], ip,Ids[i], roads);
        ThreadArgs args;
        args.node = &nodes[i];
        args.port = ports[i];
        threads[i] = CreateThread(NULL, 0, server_thread, &args,  0, NULL);

        if (threads[i] == NULL) {
            printf("Could not create thread %d\n", i);
            for (int j = 0; j <= i; j++) {
                free_node(&nodes[j]);
            }
            free(nodes);
            return 1;
        }
    }

    SendArgs* sendArgs = malloc(sizeof(SendArgs));
    if (sendArgs == NULL) {
        printf("Failed to allocate memory for sendArgs\n");
        return -1;
    }

    sendArgs->road = &road;
    sendArgs->message = "";
    sendArgs->nodes = nodes;

    HANDLE globalThread = CreateThread(NULL, 0, global_thread, sendArgs, 0, NULL);
    threads[NUM_THREADS+1] = globalThread;

    WaitForMultipleObjects(NUM_THREADS + 2, threads, TRUE, INFINITE);

    for (int i = 0; i < NUM_THREADS+2; i++) {
        CloseHandle(threads[i]);
    }

    /*for (int i = 0; i < NUM_THREADS; i++) {
        free_node(&nodes[i]);
    }
    /*free(nodes);*/
    WSACleanup();
    return 0;
}