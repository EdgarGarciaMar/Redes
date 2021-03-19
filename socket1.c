//
//  main.c
//  tarea1
//
//  Created by Edgar Garcia on 12/03/21.
//

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>

int main(int argc, const char * argv[]) {
    int udp_socket, lbind, tam;
    struct sockaddr_in local, remota;
    unsigned char msj[100]="Hola red";
    udp_socket=socket(AF_INET,SOCK_DGRAM,0);
    if(udp_socket==-1){
        perror("\n Error al abrir el socket");
        exit(0);
    }else{
        perror("\n Exito al abrir el socket");
        local.sin_family=AF_INET;
        local.sin_port=htons(0);
        local.sin_addr.s_addr=INADDR_ANY;
        lbind=bind(udp_socket, (struct sockaddr *)&local, sizeof(local));
        if(lbind==-1){
            perror("\n Error en biind");
            exit(0);
        }
        else{
            perror("\n Exito en bind");
            remota.sin_family=AF_INET;
            remota.sin_port=htons(53);
            remota.sin_addr.s_addr=inet_addr("8.8.8.8");
            tam=sendto(udp_socket, msj, 20, 0, (struct sockaddr *)&remota, sizeof(remota));
            if(tam==-1){
                perror("\n Error al enviar");
                exit(0);
            }
            else{
                perror("\n Exito al enviar");
            }
        }
            
    }
    close(udp_socket);
    return 0;
}
