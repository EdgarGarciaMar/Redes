#include<sys/socket.h>
#include<sys/types.h>
#include<arpa/inet.h>
#include<stdio.h>
#include<errno.h>
#include<sys/ioctl.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<linux/if_packet.h>
#include<net/if.h>
#include<net/ethernet.h>
struct ifreq nic;
FILE *puerta;
struct DatosRed{
	char NomInterfaz[10];
	int indice;
	unsigned char MAC[6];
	unsigned char IPOrigen[4];
        unsigned char PuertaEnlace[4];
        unsigned char MacPuertaEnlace[4];
	unsigned char Mascara[6];
};
int ObtenerIndice( int ds,struct DatosRed *datos){
    int indice;
    if ( ioctl(ds,SIOCGIFINDEX,&nic)==-1){
	perror("\nError al obtener el indice");
	exit(1);
    }
    else{
        datos->indice=nic.ifr_ifindex;
        indice=datos->indice;
    }
return indice;
}
void ObtenerMac(int ds,struct DatosRed *datos){
    if ( ioctl(ds,SIOCGIFHWADDR,&nic)==-1){
        perror("\nError al obtener la MAC");
        exit(1);
    }
    else{
        memcpy(datos->MAC,nic.ifr_hwaddr.sa_data,6);
    }
}
void ObtenerIp(int ds,struct DatosRed *datos){
    int i;
    if ( ioctl(ds,SIOCGIFADDR,&nic) ==-1){
        perror("\nError al obtener la IP");
        exit(1);
    }
    else{
        memcpy(datos->IPOrigen,nic.ifr_addr.sa_data+2,4);
    }
}
void ObtenerMascara(int ds, struct DatosRed *datos){
    if(ioctl(ds,SIOCGIFNETMASK,&nic)==-1){
        perror("\nError al obtener la mascara"); 
	exit(1);
    }
    else
        memcpy(datos->Mascara,nic.ifr_netmask.sa_data+2,6);
}
void ObtenerPuertaEnlace(int ds, struct DatosRed *datos){
    system("arp -an > MACdoor.txt");
    if((puerta=fopen("MACdoor.txt","r"))!=NULL){
        fscanf(puerta,"? (%d.%d.%d.%d) at %x:%x:%x:%x:%x:%x",(int*)&datos->PuertaEnlace[0],(int*)&datos->PuertaEnlace[1],(int*)&datos->PuertaEnlace[2],(int*)&datos->PuertaEnlace[3],(unsigned int *)&datos->MacPuertaEnlace[0],(unsigned int *)&datos->MacPuertaEnlace[1],(unsigned int *)&datos->MacPuertaEnlace[2],(unsigned int *)&datos->MacPuertaEnlace[3],(unsigned int *)&datos->MacPuertaEnlace[4],(unsigned int *)&datos->MacPuertaEnlace[5]);
    }
    else{
        printf("\nError al abrir el archivo");exit(-1);
        
    }
        fclose(puerta);
}
void ImprimirDatos(int ds, struct DatosRed *datos){
    int i;
    printf("\nEl indice es: %d \n",datos->indice);
    printf("La direccion MAC origen es: ");
    for(i=0;i<6;i++)
        printf("%.2x:",datos->MAC[i]);			
    printf("\n");
    printf("La dirección IP origen es: ");
    for (i=0;i<4;i++)
        printf("%d.",datos->IPOrigen[i]);
    printf("\n");
    printf("La mascara de subred es: ");
    for(i=0;i<4;i++)
        printf("%d.",datos->Mascara[i]);
    printf("\n");
    printf("La Puerta de enlace es: ");
    for(i=0;i<6;i++)
        printf("%.2x:",datos->PuertaEnlace[i]);			
    printf("\n");
    printf("La MAC de la puerta de enlace es: ");
    for(i=0;i<6;i++)
        printf("%.2x:",datos->MacPuertaEnlace[i]);			
    printf("\n");
    //system("ip r | grep default");
    //system("cat /etc/resolv.conf | grep nameserver");
}