#include <sys/socket.h>
#include <sys/types.h> 
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> 
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/time.h>

unsigned char MACOrigen[6];
unsigned char IPOrigen[4];
unsigned char IPDestino[4];
unsigned char NETMASKOrigen[4];
unsigned char CadenaIngresada[4];
unsigned char TramaEnviar[60]={0xff,0xff,0xff, 0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x06,0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x01,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,'E','G','M'};
unsigned char TramaRecibida[1514];
unsigned char MACBroad[6]={0xff,0xff,0xff,0xff,0xff,0xff};
unsigned char Ethertype[2]={0x08,0x06};
unsigned char CodARPRes[2]={0x00,0x02};
char IPRecibida[9]="";
char MACRecibida[13]="";

void Documento(unsigned char *trama, FILE *archivo){
    for(int i= 0; i<6 ; ++i){
        sprintf(MACRecibida+(i*2), "%02x", trama[i+22]);
    }
    MACRecibida[13] = '\0';
	sprintf(IPRecibida,"%d.%d.%d.%d",trama[28],trama[29],trama[30],trama[31]);		
    /*for(int i= 0; i<4 ; ++i){
        sprintf(IPRecibida+(i*3), "%d", trama[i+28]);
    }*/
    IPRecibida[13] = '\0';
    fputs("IP: ", archivo);
    fputs(IPRecibida, archivo);
    fputs(" MAC: ", archivo);
    fputs(MACRecibida, archivo);
    fputc('\n', archivo);
    printf("\nGuardado en archivo");
}

void ImprimirMAC(unsigned char *paq, int len){
	for(int i=6;i<len;i++){
		if(i%16==0)
			printf("\n");
		printf("%.2x ",paq[i]);
	} 
	printf("\n");
} 

void ImprimirTrama(unsigned char *paq, int len){
	for(int i=0;i<len;i++){
		if(i%16==0)
			printf("\n");
		printf("%.2x ",paq[i]);
	} 
	printf("\n");
}

int FiltroARP(unsigned char *paq, int len){
	if(!memcmp(paq,MACOrigen,6) && !memcmp(paq+12,Ethertype,2)  && !memcmp(paq+20,CodARPRes,2) && !memcmp(paq+28,IPDestino,4) && !memcmp(paq+38,IPOrigen,4)){
        return 1;
	} else {
		return 0;
	}
}

void RecibirTrama(int ds, unsigned char *trama, FILE *archivo){
	int tam, flag=0;
	struct timeval start, end;
 	long mtime=0, seconds, useconds;

 	gettimeofday(&start, NULL);
 	while(mtime<300){
		tam=recvfrom(ds,trama,1514, MSG_DONTWAIT,NULL,0);
        flag=FiltroARP(trama, tam);
        if(flag==1){
            ImprimirTrama(trama,60);
            Documento(trama, archivo);
            break;
        }
		gettimeofday(&end, NULL);
 		seconds= end.tv_sec - start.tv_sec;
 		useconds= end.tv_usec - start.tv_usec;
 		mtime= ((seconds)*1000 + useconds/1000.0) + 0.5;
	}
	if(mtime<100)
        printf(" Tiempo de respuesta: %ld\n",mtime);
	if(mtime>=100)
        printf(" Tiempo de espera Terminado: %ld\n",mtime);
}

void estructuraTrama(unsigned char *trama){
	//Encabezado MAC
	memcpy(trama+6, MACOrigen, 6);
	//Mensaje ARP
	memcpy(trama+22,MACOrigen,6);
	memcpy(trama+28,IPOrigen,4);
	memcpy(trama+32,"0x00",6);
	memcpy(trama+38,IPDestino,4);
}

int ObtenerDatos(int ds, int i, unsigned char *nombre){
 	struct ifreq nic;
 	int index;
 	
 	strcpy(nic.ifr_name,nombre); //Rellenando la estructura ifreq
 	if(ioctl(ds,SIOCGIFINDEX,&nic)==-1){
 		perror("\nError al obtener el indice");
 		exit(0);
 	} else {
 		index=nic.ifr_ifindex;
 		/*printf("\nEl indice es: %d\n",index);*/
 		
 		if(ioctl(ds,SIOCGIFHWADDR,&nic)==-1){ 
 			perror("\nError al obtener la MAC");
 			exit(0);
 		} else {
 			memcpy(MACOrigen, nic.ifr_hwaddr.sa_data,6);
 			/*printf("\nLA MAC es: ");
 			for(int i=0;i<6;i++){
 				printf("%.2x:",MACOrigen[i]);
 			} 
 			printf("\n");*/
            
 			if(ioctl(ds,SIOCGIFADDR,&nic)==-1){ 
 				perror("\nError al obtener IP");
 			} else {
                memcpy(IPOrigen, nic.ifr_addr.sa_data+2, 4);
                /*printf("\n La IP es: ");
                for(int i=0;i<4;i++){
                    printf("%d.",IPOrigen[i]);
                } 
                printf("\n");*/	

 			if(ioctl(ds,SIOCGIFNETMASK,&nic)==-1){ //obtener NETMASKOrigen de red
 				perror("\nError al obtener la NETMASKOrigen");
 			} else {
                memcpy(NETMASKOrigen, nic.ifr_netmask.sa_data+2, 4);
                /*printf("\n La NETMASKOrigen es: ");
                for(int i=0;i<4;i++){
 					printf("%d.",NETMASKOrigen[i]);
                } 
                printf("\n");*/	
 			}
 		}
 	}
 } 
    memcpy(IPDestino,IPOrigen,4);
    IPDestino[3]=i;
    return index;
}


void EnviarTrama(unsigned char *trama, int ds,int index){ 
    int tam;
    struct sockaddr_ll CapaARP;
    memset(&CapaARP,0x00,sizeof(CapaARP));
    CapaARP.sll_family=AF_PACKET;
    CapaARP.sll_protocol=htons(ETH_P_ALL);
    CapaARP.sll_ifindex=index;
    tam=sendto(ds, trama, 60, 0, (struct sockaddr *)&CapaARP, sizeof(CapaARP));
    if(tam==-1){
        perror("\nError al enviar");
        exit(0);
    } else {
        perror ("\nExito al enviar");
    }
}

void scannerARP(int ds){
	char c;
    int indice, opc; 
    unsigned char nombreInter[20];
    
	FILE* archivo,* lector;
	archivo = fopen("ScannerARP.txt", "w+");
	lector = fopen("ScannerARP.txt", "r");
	if(archivo==NULL){
		printf("\nError al crear el archivo");
		exit (0);
	}
 	printf("\nInserta el nombre de la interfaz: ");
 	gets(nombreInter);
	for(int i=1 ; i<=255 ; ++i){
		indice=ObtenerDatos(ds, i,nombreInter);
		printf("\n");
		estructuraTrama(TramaEnviar);
		EnviarTrama(TramaEnviar,ds,indice);
		RecibirTrama(ds,TramaRecibida, archivo);
	}
	fclose(archivo);
	system("clear");
	while((c=fgetc(lector))!= EOF){
		putchar(c);
	} 
	printf("\n");
	printf("\n");
	fclose(lector);
}

int main(){
	int packet_socket; 
	packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(packet_socket==-1){
		perror("\nError al abrir el socket");
		exit(0);
	} else {
		scannerARP(packet_socket);
		printf("\nDatos almacenados en el archivo: ScannerARP.txt\n");
	}

	close(packet_socket);
	return 0;
}
