#include"Datos.h"
#include <sys/time.h>

int LocalizarSubred();
void SolicitudARPSubred( int ,int ,unsigned char * ,unsigned char * );
void SolicitudARPFueraSubred( int ,int ,unsigned char *,unsigned char *  );
void EnviarTramaARP( int ,int ,unsigned char * ,unsigned char *  );
int RecibeTramaARP( int  , unsigned char * );
int FiltroARP( unsigned char * );
void EstructurarTrama( int , unsigned char * );
void EstablecerID( unsigned char * , unsigned char * );
void CalcularChecksum( unsigned char * );
void EnviarTrama( int ,int ,unsigned char * ,unsigned char * );
int RecibeTrama( int ds,unsigned char * );
int Filtro(unsigned char *);
void Estadistica();
void ImprimeTrama(unsigned char *trama, int tam);
    
struct DatosRed Datos;

long Tiempo[4];
int PaquetesRecibidos=0;
unsigned char IpDestino[4],MacDestino[6],Mask[4]={255,255,224,0};

int main(){
    int packet_socket,indice,TipoARP,i;
    unsigned char TramaEnv[1514],TramaRcv[1514],TramaARP[1514],TramaARPResp[1514];
    memset(Tiempo,0,4);
    printf("\t\t\t\t\t---Ping---\n");
    packet_socket=socket ( AF_PACKET, SOCK_RAW , htons ( ETH_P_ALL ) );
    if ( packet_socket == -1 ){
        perror("\nError al abrir el socket");
        exit(1);
    }
    else{
        printf("\nInserta el nombre de la interfaz: ");
        scanf("%s",Datos.NomInterfaz);
        strcpy(nic.ifr_name,Datos.NomInterfaz);
        ObtenerIndice(packet_socket,&Datos);
	    ObtenerMac(packet_socket,&Datos);
        ObtenerIp(packet_socket,&Datos);
        ObtenerMascara(packet_socket,&Datos);
        ObtenerPuertaEnlace(packet_socket,&Datos);
        indice=Datos.indice;
        //ImprimirDatos(packet_socket,&Datos);
    }
    printf("\nIP Destino: ");
    scanf("%hhu.%hhu.%hhu.%hhu",IpDestino,IpDestino+1,IpDestino+2,IpDestino+3);
    /*TipoARP = LocalizarSubred();
    if( TipoARP )
        SolicitudARPSubred(packet_socket,indice,TramaEnv,TramaRcv);
    else*/
        SolicitudARPFueraSubred(packet_socket,indice,TramaEnv,TramaRcv);
    for(i=0; i< 4; i++){
            EstructurarTrama(i,TramaEnv);
            EnviarTrama(packet_socket,indice,TramaEnv,TramaRcv);
    }
    Estadistica(PaquetesRecibidos);
    close(packet_socket);
return 0;
}

int LocalizarSubred (){
    unsigned char A[4],B[4];
    int i;
    memset(A,0,4);
    memset(B,0,4);
    for ( i=0 ; i<4 ; i++)
        A[i] = IpDestino[i]&(Datos.Mascara[i]);//A[i] = IpDestino[i]&Mask[i];
    for ( i=0 ; i<4 ; i++)
        B[i] = (Datos.IPOrigen[i])&(Datos.Mascara[i]);//B[i] = (Datos.IPOrigen[i])&Mask[i];
    if(!memcmp(A,B,4)){
        printf("\nDentro de la subred");
        return 1;
    }
    else{
        printf("\nFuera de Subred");
        return 0;
    }
}
void SolicitudARPSubred( int ds,int indice,unsigned char * TramaARP,unsigned char * TramaARPResp ){
    unsigned char Broadcast[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},MACcero[6]={0x00,0x00,0x00,0x00,0x00,0x00};
    unsigned char Eth[2]={0x08,0x06},TH[2]={0x00,0x01},PIP[2]={0x08,0x00},LH=0x06,LP=0X04,CO[2]={0x00,0x01};
    memset(TramaARP,0,1514);
    memcpy(TramaARP,Broadcast,6);
    memcpy(TramaARP+6,Datos.MAC,6);
    memcpy(TramaARP+12,Eth,2);
    memcpy(TramaARP+14,TH,2);
    memcpy(TramaARP+16,PIP,2);
    memcpy(TramaARP+18,&LH,1);
    memcpy(TramaARP+19,&LP,1);
    memcpy(TramaARP+20,CO,2);
    memcpy(TramaARP+22,Datos.MAC,6);
    memcpy(TramaARP+28,Datos.IPOrigen,4);
    memcpy(TramaARP+32,MACcero,6);
    memcpy(TramaARP+38,IpDestino,4);
    EnviarTramaARP(ds,indice,TramaARP,TramaARPResp);
}
void SolicitudARPFueraSubred( int ds,int indice,unsigned char * TramaARP,unsigned char * TramaARPResp ){
    unsigned char Broadcast[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},MACcero[6]={0x00,0x00,0x00,0x00,0x00,0x00};
    unsigned char Eth[2]={0x08,0x06},TH[2]={0x00,0x01},PIP[2]={0x08,0x00},LH=0x06,LP=0X04,CO[2]={0x00,0x01};
    memset(TramaARP,0,1514);
    memcpy(TramaARP,Broadcast,6);
    memcpy(TramaARP+6,Datos.MAC,6);
    memcpy(TramaARP+12,Eth,2);
    memcpy(TramaARP+14,TH,2);
    memcpy(TramaARP+16,PIP,2);
    memcpy(TramaARP+18,&LH,1);
    memcpy(TramaARP+19,&LP,1);
    memcpy(TramaARP+20,CO,2);
    memcpy(TramaARP+22,Datos.MAC,6);
    memcpy(TramaARP+28,Datos.IPOrigen,4);
    memcpy(TramaARP+32,MACcero,6);
    memcpy(TramaARP+38,Datos.PuertaEnlace,4);
    EnviarTramaARP(ds,indice,TramaARP,TramaARPResp);
}
void EnviarTramaARP( int ds,int index,unsigned char * TramaARP, unsigned char * TramaARPResp ){
    int tam;
    struct sockaddr_ll capaEnlace;
    memset(&capaEnlace,0x00,sizeof(capaEnlace));
    capaEnlace.sll_family=AF_PACKET;
    capaEnlace.sll_protocol=htons(ETH_P_ALL);
    capaEnlace.sll_ifindex=index;
    tam = sendto(ds,TramaARP,48,0,(struct sockaddr*)&capaEnlace,sizeof(capaEnlace));
    if(tam==-1){
        perror("\nError al enviar trama ARP");
        exit(1);
    }
    else{
        if ( RecibeTramaARP(ds,TramaARPResp) ) {
            printf("\nError de ARP\n");
            exit(1);
        }
    }
    
}
int RecibeTramaARP( int ds , unsigned char * TramaARPResp ){
    int tam, bandera=0;
    struct timeval start, end; 
    long mtime=0, seconds, useconds;
    gettimeofday(&start,NULL);
    while( mtime < 700 ){
        tam=recvfrom(ds,TramaARPResp,1514,MSG_DONTWAIT,NULL,0);
        if(tam==-1){
            bandera=0;
            //perror("\nError al recibir");
            //break;
        }
        else{
            bandera=FiltroARP(TramaARPResp);
            if (bandera==1){
                //printf("Elapsed time: %ld milliseconds\n", mtime);
                memcpy(MacDestino,TramaARPResp+6,6);
                return 0;
            }
        }
        gettimeofday(&end, NULL);
        seconds  = end.tv_sec  - start.tv_sec;
        useconds = end.tv_usec - start.tv_usec;
        mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;
    }
    printf("\nTiempo de ARP agotado...\n");
    return 1;
}
int FiltroARP( unsigned char * TramaARPResp ){
    unsigned char Eth[2]={0x08,0x06},COR[2]={0x00,0x02};
    if( !memcmp(TramaARPResp,Datos.MAC,6) && !memcmp(TramaARPResp+12,Eth,2) && !memcmp(TramaARPResp+20,COR,2) && !memcmp(TramaARPResp+38,Datos.IPOrigen,4) )
        return 1;
    else
        return 0;
}
void EstructurarTrama( int i , unsigned char * TramaEnv ){
    unsigned char EthPing[2]={0x08,0x00},Version=0x45,TipoServicio=0x00,Longitud[2]={0x00,0x20},Banderas_Desplazamiento[2]={0x40,0x00},TTL=0x80,Protocolo=0x01;
    unsigned char TipoSol=0x08,Codigo=0x00,datos[8]={"EDGM"};
    unsigned char IdDatagrama[2],Checksum[2]={0x00,0x00},ChecksumIP[2]={0x00,0x00},IdICMP[2],NS[2]={0x00,0x00};
    memset(TramaEnv,0,1514);
    EstablecerID(IdDatagrama,IdICMP);
    NS[1]=i;
    
    //Trama Ethernet
    memcpy(TramaEnv,MacDestino,6);
    memcpy(TramaEnv+6,Datos.MAC,6);
    memcpy(TramaEnv+12,EthPing,2);
    memcpy(TramaEnv+14,&Version,1);
    //Trama IP
    memcpy(TramaEnv+15,&TipoServicio,1);
    memcpy(TramaEnv+16,Longitud,2);
    memcpy(TramaEnv+18,IdDatagrama,2);
    memcpy(TramaEnv+20,Banderas_Desplazamiento,2);
    memcpy(TramaEnv+22,&TTL,1);
    memcpy(TramaEnv+23,&Protocolo,1);
    memcpy(TramaEnv+24,ChecksumIP,2);
    memcpy(TramaEnv+26,Datos.IPOrigen,4);
    memcpy(TramaEnv+30,IpDestino,4);
    //Trama ICMP
    memcpy(TramaEnv+34,&TipoSol,1);
    memcpy(TramaEnv+35,&Codigo,1);
    memcpy(TramaEnv+36,Checksum,2);
    memcpy(TramaEnv+38,IdICMP,2);
    memcpy(TramaEnv+40,NS,2);
    memcpy(TramaEnv+42,datos,8);
    CalcularChecksum(TramaEnv);
}
void EstablecerID( unsigned char *IdDatagrama , unsigned char *IdICMP ){
    IdICMP[1]=getpid() >> 4;
    IdDatagrama[1]=getpid() >> 4;
}
void CalcularChecksum( unsigned char * trama ) {
    unsigned int aux=0x00,aux2=0x00,pre,chec;
    int i;
    //PARA IP
    for(i=14;i<34;i=i+2)
	aux=aux+*(trama+i);	
    for(i=15;i<=34;i=i+2)
	aux2=aux2+*(trama+i);
    //printf("Suma: %x %x\n",aux,aux2);
    if((aux2 >> 8) > 0x00)
        aux = aux + (aux2 >> 8);
    aux2=aux2 & 0x00ff;		
    if((aux >> 8) > 0x00)
        aux2 = aux2 + (aux >> 8);
    aux=aux & 0x00ff;
    aux=~aux;
    aux2=~aux2;
    *(trama+24)=aux;
    *(trama+25)=aux2;	
    //PARA ICMP
    aux=0x00;aux2=0x00;
    for(i=34;i<49;i=i+2)
        aux=aux+*(trama+i);
    for(i=35;i<=49;i=i+2)
        aux2=aux2+*(trama+i);
    if((aux2 >> 8) > 0x00)
        aux = aux + (aux2 >> 8);
    aux2=aux2 & 0x00ff;
    if((aux >> 8) > 0x00)
        aux2 = aux2 + (aux >> 8);
    aux=aux & 0x00ff;
    aux=~aux;
    aux2=~aux2;
    *(trama+36)=aux;
    *(trama+37)=aux2;
}
void EnviarTrama( int ds,int index,unsigned char * TramaEnv,unsigned char * TramaRcv ){
    int tam;
    struct sockaddr_ll capaEnlace;
    memset(&capaEnlace,0x00,sizeof(capaEnlace));
    capaEnlace.sll_family=AF_PACKET;
    capaEnlace.sll_protocol=htons(ETH_P_ALL);
    capaEnlace.sll_ifindex=index;
    tam = sendto(ds,TramaEnv,46,0,(struct sockaddr*)&capaEnlace,sizeof(capaEnlace));
    if(tam==-1){
        perror("\nError al enviar trama");
        exit(1);
    }
    else{
        if( RecibeTrama(ds,TramaRcv) ){
            printf("\n No hubo respuesta\n");
        }
    }
}
int RecibeTrama( int ds,unsigned char *TramaRcv ){
    int tam, bandera=0,i=0;
    struct timeval start, end; 
    long mtime=0, seconds, useconds;
    gettimeofday(&start,NULL);
    
    while(mtime < 2500 ){
        tam=recvfrom(ds,TramaRcv,1514,MSG_DONTWAIT,NULL,0);
        if(tam==-1){
            bandera=0;
            //perror("\nError al recibir");
            //break;
        }
        else{
            bandera=Filtro(TramaRcv);
            if (bandera){
                printf("\nRespuesta desde la IP: %d.%d.%d.%d", TramaRcv[26],TramaRcv[27],TramaRcv[28],TramaRcv[29]);
                printf(": tiempo=%ldms ttl=%d",mtime,TramaRcv[22]);
                Tiempo[PaquetesRecibidos]=mtime;
                PaquetesRecibidos=PaquetesRecibidos+1;
                return 0;
            }
        }
        gettimeofday(&end, NULL);
        seconds  = end.tv_sec  - start.tv_sec;
        useconds = end.tv_usec - start.tv_usec;
        mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;
    }
    return 1;
}
int Filtro(unsigned char *trama){
    if(!memcmp(trama+0,Datos.MAC,6)&&!memcmp(trama+6,MacDestino,6))
        return 1;
    else
        return 0;
}
void Estadistica( ){
    int media=0,aux,i,j;
    for(j=0;j<4;j++){
        for(i=0;i<3;i++){
            if(Tiempo[i]<Tiempo[i+1]){
                aux=Tiempo[i];
                Tiempo[i]=Tiempo[i+1];
                Tiempo[i+1] = aux;
            }
        }
    }
    media= ( Tiempo[0]+Tiempo[1]+Tiempo[2]+Tiempo[3] )/4;
    printf("\n");
    printf("\n\t\t\t\t---Estadísticas del Ping---\n");
    printf("\t\tPaquetes de: 4 bytes, Paquetes enviados=%d, Recibidos=%d, Perdidos=%d\n",4,(PaquetesRecibidos),(4-PaquetesRecibidos));
    printf("\n");
    printf("\n\t\t\t---Porcentaje de paquetes perdidos en el camino---\n");
    printf("\t\t\t\t\t(%d %% perdidos)\n",( ( 4-PaquetesRecibidos ) *100 ) / 4);
    printf("\n");
    printf("\t\t\t---Tiempo aproximado de ida y vuelta en ms.---\n");
    printf("\t\t\t\tmaximo=%ldms, minimo=%ldms, media=%d\n\n",Tiempo[0],Tiempo[3],media);
}
void ImprimeTrama(unsigned char *trama, int tam){
    int i;
    for(i=0;i<tam;i++){
        if(i%16==0)
            printf("\n");
	printf(" %.2x",trama[i]);
    }	
    printf("\n");
}
