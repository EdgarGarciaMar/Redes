       #include <stdio.h>
       #include <stdlib.h>
       #include <sys/socket.h>
       #include <linux/if_packet.h>
       #include <net/ethernet.h> /* the L2 protocols */
       #include <arpa/inet.h>
       #include <unistd.h>
       #include <sys/ioctl.h>
       #include <net/if.h>
        #include <string.h>


       
void obtenerDatos( int ds){//funcion para obtener el index
    struct ifreq nic;
    unsigned char nombre[20];
    printf("\n Ingresa el nombre del la interfaz \n");
    scanf("%s",nombre);
    strcpy(nic.ifr_name,nombre);//copea el string
    if(ioctl(ds,SIOCGIFINDEX,&nic)==-1){
        perror("\n Error al obtener el index");
        exit(0);
    }
    else{
        printf("\nLa direccion es: %d\n",nic.ifr_ifindex);
    }
}
int main()
{
int packet_socket;//socket crudo
packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
if(packet_socket == -1){
perror("\n Error al abrir el socket");
exit(0);
}
else {
perror("\n Exito al abrir el socket\n");
obtenerDatos(packet_socket);
}
close(packet_socket);
return 0;
}
