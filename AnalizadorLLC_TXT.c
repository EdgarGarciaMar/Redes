#include"Datos.h"

struct DatosRed Datos;

void EnviarTrama( int ds,int index,unsigned char *);
void RecibeTrama(int ds,int ,unsigned char *);
int FiltroLLC(unsigned char *, int);
void EstructurarTramaLLC(unsigned char *);
void ImprimeTrama(unsigned char *, int ,int);
void AnalizarTrama(unsigned char *);
void ObtenerMACs(unsigned char *);
void Longitud(unsigned char *trama);
void DSAP_SSAP(unsigned char  , unsigned char );
int Tipo_Trama(unsigned char );
int Caso_1byte(unsigned char );
int Caso_2bytes(unsigned char, unsigned char  , unsigned char , int);
void ObtenerTramas( int ds, int index, unsigned char *trama,unsigned int *);

int main(){
    unsigned char TramaLLC[1514];
    unsigned int TramaAux[1514];
    int packet_socket,indice;
    printf("\t\t\t\tAnalizador de Tramas LLC\n");
    packet_socket=socket ( AF_PACKET, SOCK_RAW , htons ( ETH_P_ALL) );
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
        indice=Datos.indice;
        //RecibeTrama(packet_socket,indice,TramaLLC);
        ObtenerTramas( packet_socket, indice, TramaLLC,TramaAux);
    }
    close(packet_socket);
return 0;
}
void RecibeTrama(int ds ,int indice, unsigned char *trama ){
    int tam, bandera,NoTrama=1;
    while(1){
        tam=recvfrom(ds,trama,1514,0,NULL,0);
        if( (trama[12]<<8)+trama[13] < 1500 ){
            printf("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
            printf("Trama %d\n",NoTrama);
            AnalizarTrama(trama);
            //ImprimeTrama(trama,tam);
            NoTrama++;
        }
    }
}
void AnalizarTrama(unsigned char *trama){
    int Tipo;
    ObtenerMACs(trama);
    Longitud(trama);
    DSAP_SSAP(trama[14],trama[15]);
    Tipo=Tipo_Trama(trama[16]);
    if(Tipo==0 || Tipo==2)
        Caso_2bytes(trama[15],trama[16],trama[17],0);
    if(Tipo==1)
    	Caso_2bytes(trama[15],trama[16],trama[17],1);
    if(Tipo==3)
        Caso_1byte(trama[16]);
}
void ObtenerMACs(unsigned char *trama){
    unsigned char MACdestino[6],MACorigen[6];
    memcpy(MACdestino,trama+0,6);
    memcpy(MACorigen,trama+6,6);
    printf("\tLa MAC destino es: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",MACdestino[0],MACdestino[1],MACdestino[2],MACdestino[3],MACdestino[4],MACdestino[5]);
     printf("\tLa MAC origen es: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",MACorigen[0],MACorigen[1],MACorigen[2],MACorigen[3],MACorigen[4],MACorigen[5]);
}
void Longitud(unsigned char *trama){
	printf("\tLongitud: %d\n", ((trama[12]<<8) + trama[13]));
}
void DSAP_SSAP(unsigned char I_G , unsigned char C_R){
    if((I_G&0x01)==1)
    	printf("\tTrama de grupo.\n");
    else
    	printf("\tTrama individual.\n");
    if((C_R&0x01)==1)
    	printf("\tTrama de respuesta\n");
    else
    	printf("\tTrama de comando\n");
    printf("\tDSAP y SSAP: ");
    switch((I_G&0xFE)){//0xFE= 254 = 11111111
    
        case 0x00:
            printf("Null LSPA\n");
            break;
        case 0x02:
            printf("Individual LLC Sublayer Management Function");
            break;
        case 0x03:
            printf("Group LLC Sublayer Managament Function");
        case 0x04:
            printf("IBM SNA Path Control (Individual)\n");
            break;
        case 0x05:
            printf("IBM SNA Path Control (Group)\n");
            break;
	case 0x06:
            printf("IP\n");
            break;
        case 0x0E:
            printf("PROWAY (IEC955) NEtwork Managament & Initialization\n");
            break;
        case 0x18:
            printf("Texas Intruments\n");
            break;
        case 0x4E:
            printf("EIA RS-511 Manufacturing Message Service\n");
            break;
        case 0x7E:
            printf("ISO 8208 (X.25 over IEEE 802.2 Type 2 LLC)\n");
            break;
        case 0x80:
            printf("Xerox Network Systems (XNS)\n");
            break;
        case 0x86:
            printf("Nestar\n");
            break;
        case 0x8E:
            printf("PROWAY (IEC 955) Active Station List Maintenance\n");
            break;
        case 0x98:
            printf("ARPANET Address Resolution Protocol (ARP)\n");
            break;
        case 0xBC:
            printf("Banyan VINES\n");
            break;
        case 0xAA:
            printf("SubNetwork Access Protocol (SNAP)\n");
            break;
        case 0xE0:
            printf("Novell NetWare\n");
            break;
        case 0xF0:
            printf("IBM NetBIOS\n");
            break;
        case 0xF4:
            printf("IBM LAN Management (individual)\n");
            break;
        case 0xF5:
            printf("IBM LAN Management (group)\n");
            break;
        case 0xF8:
            printf("IBM Remote Program Load (RPL)\n");
            break;
        case 0xFA:
            printf("Ungermann-Bass\n");
            break;
        case 0xFE:
            printf("ISO Network Layer Protocol\n");
            break;
        case 0xFF:
            printf("Global LSAP\n");
            break;
        default:
            printf("ERROR\n");
    }

}
int Tipo_Trama(unsigned char env){
    switch((env&0x03))
    {
            case 0:printf("\tTrama de informacion\n");
                return 0;
                break;
            case 1:printf("\tTrama de supervicion\n");
                return 1;
                break;
            case 2:printf("\tTrama de informacion\n");
                return 2;
                break;
            case 3:printf("\tTrama no numerada\n");
                return 3;
                break;
    }
    return 5;
}
int Caso_1byte(unsigned char byte1){
        if((byte1&0xFF)==16){ //0x10 = 00010000
            printf("\tRequiere un respuesta inmediata\n");
        }
        else{
            printf("\tTipo de trama no numerada:\n");
        }
            switch((byte1&0xFF)){ //0xEC = 236 = 11101100 
                case 0x93:printf("\tSet normal response SNRM"); //10010011
                    break;
                case 0x6F:printf("\tSet normal response extended mode SNRME\n"); //1101111
                    break;
                case 0x01F:printf("\tSet asincronous response SARM\n"); //00011111
                    break;
                case 0x5F:printf("\tSet asincronous response extended mode SARME\n");//01011111
                    break;
                case 0x3F:printf("\tSet asincronous balance mode SABM\n");//00111111
                    break;
                case 0x7F:printf("\tSet asincronous balance extended mode SABME\n");//01111111
                    break;
                case 0x17:printf("\tSet inicialitation mode SIM\n");//00010111
                    break;
                case 0x53:printf("\tDisconect DIST\n"); //01010011
                    break;
                case 0x33:printf("\tUnnumbered poll up\n"); //00110011
                    break;
                case 0x9F:printf("\tReset\n"); //10011111
                    break;
                case 0x13:printf("\n\tUnnumered informacion ui"); //00010011
                    break;
                case 0xBF:printf("\n\tExchange identification xid"); //10111111
                    break;
                case 0xF3:printf("\n\tTest"); // 11110011
                    break;
                case 0x73:printf("\tUnnumbered Acknowledgment UA"); //01110011
                    break;
                case 0x0F:printf("\tDisconect mode DM"); //00001111
                    break;
                case 0x43:printf("\tRequest disconect RD"); //01000011
                    break;
                case 0x07:printf("\tRequest initialitacion mode RIM"); //00000111
                    break;
                case 0x03:printf("\n\tUnnumered informacion ui"); //00000011
                    break;
                case 0xAF:printf("\n\tExchange identification xid"); //10101111
                    break;
                case 0xE3:printf("\n\tTest"); //11100011
                    break;
                default: printf("\n\tNo aparace en la tabla");
                    break;
            }
        printf("\n");
        if(byte1&0x04 == 1) 
            printf("\tPOLL/FINAL: F\n");
        else 
            printf("\tPOLL/FINAL: P\n");
return 0;
}
int Caso_2bytes(unsigned char SSAP,unsigned char byte1,unsigned char byte2,int opc){//opc 0 informacion 1 supervicion
    int p;
    if(opc)
    {
        switch((byte1&0x0C)){
            case 0:printf("\n\tReceiver ready (rr)");
                break;
            case 4:printf("\n\tReceiver not ready (rnr)");
                break;
            case 8:printf("\n\tRetransmicion (rej)");
                break;
            case 12:printf("\n\tRetransmicion selectiva (srej)");
                break;
        }
        printf("\n\tNúmero de secuencia que se espera recibir: %d",((byte2&0xFE)>>1));
    }
    else{
        printf("\n\tNúmero de secuencia de envio: %d",((byte1&0xFE)>>1)); //0xFE=254=11111110
        printf("\n\tNúmero de secuencia que se espera recibir: %d",((byte2&0xFE)>>1));//(byte2)/2)
        printf("\n");
    }
    p=(byte2&0x01);
    if ( p == 0)
        printf("\n\tPOLL/FINAL: 0"); 
    else{
        if ( (SSAP&0x01) == 1 )
            printf("\n\tPOLL/FINAL: F");
        else
            printf("\n\tPOLL/FINAL: P");
            
    }
return 0;
}
void ImprimeTrama(unsigned char *trama, int tam,int j){
	int i;
        printf("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
        printf("No Trama: %d",j);
	for(i=0;i<tam;i++){
		if(i%16==0)
		printf("\n");
		printf(" %.2x",trama[i]);
	}	
	printf("\n");
}

void ObtenerTramas( int ds, int index, unsigned char *trama, unsigned int *Trama_aux){
    int i,tam,j=1;;
    unsigned char trama_aux2[16];
    FILE *Archivo;
    memset(trama,0x20,1514);
    Archivo = fopen ("Tramas.txt","r");
    if (Archivo == NULL )
        puts("El archivo no existe");
    else{
        while(feof(Archivo)==0){
            fscanf(Archivo,"%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",Trama_aux,Trama_aux+1,Trama_aux+2,Trama_aux+3,Trama_aux+4,Trama_aux+5,Trama_aux+6,Trama_aux+7,Trama_aux+8,Trama_aux+9,Trama_aux+10,Trama_aux+11,Trama_aux+12,Trama_aux+13,Trama_aux+14,Trama_aux+15,Trama_aux+16,Trama_aux+17);
            for(i=0;i<18;i++)
                trama_aux2[i] = ( unsigned char ) Trama_aux[i];
            for(i=0;i<18;i++)
                trama[i]=trama_aux2[i];
            ImprimeTrama(trama,56,j/*tam*/);
            AnalizarTrama(trama);
            j++;
        }
    }
    fclose(Archivo);
}
