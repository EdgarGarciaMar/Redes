       //Requiere permisos de super usuario o admin
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
       #include <sys/types.h>
       


unsigned char MACorigen[6],MASK[4],IP[4];
unsigned char MACbroad[6]={0xff,0xff,0xff,0xff,0xff,0xff};
unsigned char ethertype[2]={0x0c,0x0c};
unsigned char TramaEnv[1514];
       
int obtenerDatos( int ds){//funcion para obtener el index
    struct ifreq nic;
    int i, index;
    unsigned char nombre[20];
    printf("\n Ingresa el nombre del la interfaz:");
    scanf("%s",nombre);
    strcpy(nic.ifr_name,nombre);//copea el string
    
    //Indice de Red
    if(ioctl(ds,SIOCGIFINDEX,&nic)==-1){
        perror("\n Error al obtener el index");
        exit(0);
    }
    else{
        index=nic.ifr_ifindex;
        printf("\n El indice es: %d\n",index);
        
    }
    //Direccion MAC SIOCGIFADDR
    if(ioctl(ds,SIOCGIFHWADDR,&nic) == -1){
            perror("\n Error al obtener la MAC");
            exit(0);
        }
        else{
            memcpy(MACorigen,nic.ifr_hwaddr.sa_data,6);
            printf("\n La MAC es:\t");
            for(i=0;i<6;i++){
                printf("%.2x:",MACorigen[i]);
            }
            printf("\n");
        }
        
    //Direccion IP   SIOCGIFADDR 
    if(ioctl(ds,SIOCGIFADDR,&nic) == -1){
            perror("\n Error al obtener la IP");
            exit(0);
        }
        else{
            memcpy(IP,nic.ifr_addr.sa_data,6);
            printf("\n La IP es:\t");
            for(i=2;i<6;i++){
                printf("%2d.",IP[i]);
            }
            printf("\n");
        }
        
        //MASK   SIOCGIFNETMASK
    if(ioctl(ds,SIOCGIFNETMASK,&nic) == -1){
            perror("\n Error al obtener la MASK");
            exit(0);
        }
        else{
            memcpy(MASK,nic.ifr_netmask.sa_data,6);
            printf("\n La MASK es:\t");
            for(i=2;i<6;i++){
                printf("%2d.",MASK[i]);
            }
            printf("\n");
        }
        return index;
}

void EstructuraTrama(unsigned char *trama){
    memcpy(trama+0,MACbroad,6);
    memcpy(trama+6,MACorigen,6);
    memcpy(trama+12,ethertype,6);
    memcpy(trama+14,"Edgar Garcia Marciano",22);
}

void enviarTrama(int ds, int index, unsigned char *trama){
    int tam;
    struct sockaddr_ll interfaz;
    memset(&interfaz,0x00,sizeof(interfaz));
        interfaz.sll_family=AF_PACKET;   /* Always AF_PACKET */
        interfaz.sll_protocol=htons(ETH_P_ALL ); /* Physical-layer protocol */
        interfaz.sll_ifindex=index;  /* Interface number */
    tam=sendto(ds, trama, 60, 0,(struct sockaddr *)&interfaz, sizeof(interfaz));
    if(tam==-1){
        perror("\nError al enviar la trama");
        exit(0);
    }
    else{
        printf("\nExito al enviar la trama\n");
    }
}

int main()
{
int packet_socket,indice;
packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
if(packet_socket == -1){
perror("\n Error al abrir el socket");
exit(0);
}
else {
perror("\n Exito al abrir el socket");
indice = obtenerDatos(packet_socket);
EstructuraTrama(TramaEnv);
enviarTrama(packet_socket,indice,TramaEnv);
}
close(packet_socket);
return 0;
}
