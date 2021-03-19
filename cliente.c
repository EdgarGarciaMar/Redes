#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
  int udp_socket,lbind,tam,lrecv;
  int n=1;
  struct sockaddr_in local,remota;
  unsigned char paqRec[512];
  unsigned char msj[512];
   udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
  
   if(udp_socket==-1)
     {
      perror("\nError al abrir el socket");
      exit(0);
     }
   else{
    perror("\nExito al abrir el socket");
    local.sin_family=AF_INET;
    local.sin_port=htons(0);/*socket efimero aleatorio*/
    local.sin_addr.s_addr=INADDR_ANY;/*Para que agarre la dirección ip automáticamente*/;
    lbind=bind(udp_socket,(struct sockaddr*)&local,sizeof(local));
    
    if(lbind==-1){
     perror("\nError en bind");
     exit(0);
     }else{
      perror("\nExito en bind");
      remota.sin_family=AF_INET;
      remota.sin_port=htons(8080);/*Puerto elegible*/
      remota.sin_addr.s_addr=inet_addr("172.16.109.3");
      //iniciar ciclo
      while(n!=0){
      //capturar el mensaje
      printf("\nCliente:");
      fgets(msj,512,stdin);
      
      tam=sendto(udp_socket,msj,strlen(msj)+1,0,(struct sockaddr *)&remota,sizeof(remota));
      
      if(tam==-1)
       {
        perror("\nError al enviar");
        exit(0);
       }else{
        //recibir el mensaje de respuesta
        tam=recvfrom(udp_socket,paqRec,512,0,(struct sockaddr *)&remota,&lrecv);
      
      if(tam==-1)
       {
        perror("\nError al recibir");
        exit(0);
        //imprimo el mensaje
       }else{
        printf("\nServidor: %s",paqRec);
        }
        
       }
      }
     }
    }
    
   close(udp_socket);
   return 0;
 }
