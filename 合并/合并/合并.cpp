// �ϲ�.cpp: �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <winsock2.h>

#pragma comment (lib, "ws2_32.lib")  //���� ws2_32.dll

char nowtime[100] = ""; //ȫ�ֱ��������浱ǰʱ��
char filename[100] = ""; //��־�ļ�������
char* response[] = {
	"220 beta OK\r\n",
	"250 OK\r\n",
	"250 Mail OK\r\n",
	"354 End data with <CR><LF>.<CR><LF>\r\n",
	"QUIT\r\n",
	"DATA\r\n",//5
	"\r\n.\r\n",
	"554 5.5.1 Error: no valid recipients\r\n",
	"RSET\r\n",

	//�����û���õ�����ʱ�Ȳ�ɾ
	"221 Bye\r\n",
	"502 Error: command not implemented\r\n",
	"334 dXNlcm5hbWU6\r\n",
	"334 UGFzc3dvcmQ6\r\n",
	"235 Authentication successful\r\n"
};
char message[10][10000];//Ӧ�ö������г�ʼ��
//message[0] ��������helo����
//message[1] ��������mail from����
//message[3] ���������ʼ�����
int num;//������¼�ж��ٸ��ռ���
char recvname[10][100]; //���������ռ��˵���Ϣ
int divnum; //������¼��Ϣ���ֿ��Ĵ���


void initNowtime();   //��ʼ����ǰʱ��
void writeLog(char * str);   //��д��־�ļ�
void Sends(SOCKET Sock, char* str);  //��Է�������Ϣ
char* Recvs(SOCKET Sock);//������Ϣ
int main_client(int i, SOCKET returnSock);  //���ռ��˷�����ͨ�ŵĳ���  //i��¼���ǵڼ����ռ���
                                            //returnsocket�Ƿ�������ʱ���ش�����Ϣ��socket
void printIP(SOCKET socket); //��ӡ�����׽��ֵ�Զ�̺ͱ���ip��port
int Checkmailaddr(char email[101]); //��������ַ��ʽ�Ƿ���ȷ
int returnError(char * temp1, SOCKET returnSock); //���ط������Ĵ�����Ϣ���ͻ���
                                 //temp1��Ҫ���صĴ�����Ϣ //returnSock�Ƿ��ش�����Ϣ�ĵ�ַ

int main() {
	//��¼�ռ��˵ĸ���
	printf("�������ռ��˵ĸ�����");
	scanf("%d", &num);

	//��ʼ����־�ļ�
	FILE *fp;
	initNowtime();
	sprintf(filename, "log-%s.txt", nowtime);
	if ((fp = fopen(filename, "w")) == NULL) {
		printf("fopen() error.\n");
		perror("fopen");
		exit(1);
	}
	fprintf(fp, "%s\n", nowtime);
	fclose(fp);

	char request[MAXBYTE];

	//��ʼ�� DLL
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	//�����׽���
	SOCKET servSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	//���׽���
	sockaddr_in sockAddr;
	memset(&sockAddr, 0, sizeof(sockAddr));  //ÿ���ֽڶ���0���
	sockAddr.sin_family = PF_INET;  //ʹ��IPv4��ַ
	//sockAddr.sin_addr.s_addr = inet_addr("10.122.212.26");  //�����IP��ַ //Ӧ�����������ip
	sockAddr.sin_addr.s_addr = inet_addr("127.0.0.1");  //�����IP��ַ
	sockAddr.sin_port = htons(25);  //�˿�
	bind(servSock, (SOCKADDR*)&sockAddr, sizeof(SOCKADDR));
	//�������״̬
	listen(servSock, 5);
	printf("���������������ڼ���......\n");
	SOCKADDR clntAddr;
	int nSize = sizeof(SOCKADDR);
	SOCKET clntSock = accept(servSock, (SOCKADDR*)&clntAddr, &nSize);
	printf("�����Ѿ�����\n");

	//��ӡ�ͻ��˺ͳ���ͨ�ŵ�ip�Ͷ˿ں�
	//printf("%d\n", ntohs(sockAddr.sin_port));
	printIP(clntSock);

	Sends(clntSock, response[0]);   //���� 220 beta OK\r\n

	char*temp = Recvs(clntSock);    //���յ� helo ����
	strcpy(message[0], temp);

	Sends(clntSock, response[1]);  //���� 250 OK\r\n

	temp = Recvs(clntSock); //���յ� MAIL FROM: ����
	strcpy(message[1], temp);

	Sends(clntSock, response[2]); //���� 250 Mail OK\r\n

	for (int i = 0; i < num; i++) {
		temp = Recvs(clntSock); //���յ� RCPT TO: ����
		strcpy(recvname[i], temp);
		char test[100]="";
		strncpy(test, temp+10, strlen(temp) - 13);
		if (Checkmailaddr(test) == -1) {
			Sends(clntSock, response[7]);
			printf("�ռ��˵�ַ����");
			return -1;
		}
		else {
			Sends(clntSock, response[2]); //���� 250 Mail OK\r\n
		}

	}

	Recvs(clntSock); //���յ� DATA ����

	Sends(clntSock, response[3]); //���� End data with <CR><LF>.<CR><LF>\r\n

	divnum = 0; //��ʼ��divnum
	//��ʼ��email�ļ�
	FILE *femail;
	if ((femail = fopen("email.txt", "w")) == NULL) {
		printf("fopen() error.\n");
		perror("fopen");
		exit(1);
	}

	do {
		temp = Recvs(clntSock); //���յ� ����
		fprintf(femail, "%s", temp);
		strcpy(message[3 + divnum], temp);
		divnum++;
	} while (*(temp + strlen(temp) - 1) != '\n' || *(temp + strlen(temp) - 2) != '\r' ||
		*(temp + strlen(temp) - 3) != '.' || *(temp + strlen(temp) - 4) != '\n' ||
		*(temp + strlen(temp) - 5) != '\r'); //�����Ϣ��βΪ\r\n.\r\n ,����ѭ��
	//�ر�email�ļ�
		fclose(femail);

	//�ж��ٸ��ռ��˾�ִ�ж��ٴ�
	for (int i = 0; i < num; i++) {
		main_client( i,clntSock);
	}

	Sends(clntSock, response[2]); //���� 250 Mail OK\r\n

	//Sends(clntSock, response[4]); //���� QUIT\r\n,�ͷ����ӣ�֮����������½������ӣ�ʹ��recv���������
								  //���ǲ�֪��Ϊʲô��ʹ��send�������������Ҳ��֪���ͻ������ӹر���û��

	//returnerror();

	//��ӡ����Ļ�ϵ�����
	printf("��ǰʱ�䣺%s\n", nowtime);
	//printIP(clntSock);
//	printf("smtp�����IP��ַ��127.0.0.1  �˿ںţ�1425\n");
	printf("�������ʼ���ַ��%s", message[1]);
	for (int i = 0; i < num; i++) {
		printf("�ռ����ʼ���ַ��%s", recvname[i]);
	}

	printf("�ʼ����ȣ�%d\n", strlen(message[3]));

	//�ر��׽���
	closesocket(clntSock);
	closesocket(servSock);
	////��ֹ DLL ��ʹ��
	WSACleanup();
	system("PAUSE");
	return 0;
}

int main_client(int i,SOCKET returnSock) {
	//�����׽���
	SOCKET clientsock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (clientsock == INVALID_SOCKET)
	{
		printf("invalid socket !");
		return 0;
	}

	sockaddr_in serAddr;

	serAddr.sin_family = PF_INET;
	serAddr.sin_port = htons(25);
	struct hostent *host;  //������Ϣ

	//������Լ�����ip
	printf("������Ŀ��IP��");
	char ip[100];
	scanf("%s", ip);
	serAddr.sin_addr.S_un.S_addr = inet_addr(ip);

	//ͨ�����õ�������ȡip
	//host = gethostbyname("mx1.bupt.edu.cn");
	//memcpy(&serAddr.sin_addr.S_un.S_addr, host->h_addr_list[0], host->h_length); //����ȡ������IP��ַ���Ƶ��ͻ��������ַ.32λ�޷���IPV4��ַ 

	if (connect(clientsock, (sockaddr *)&serAddr, sizeof(serAddr)) != 0)
	{
		printf("connect error !");
		closesocket(clientsock);
		return 0;
	}
	printf("�����������������ڷ����ʼ�\n");
	printIP(clientsock);

	if (returnError(Recvs(clientsock), returnSock) == -1) {
		return -1;
	};

	Sends(clientsock, message[0]);//����EHLO ֪ͨ�����˵��ʼ�����������
	if (returnError(Recvs(clientsock), returnSock) == -1) {
		return -1;
	};

	Sends(clientsock, message[1]);//MAIL FROM
	if (returnError(Recvs(clientsock), returnSock) == -1) {
		return -1;
	};

	Sends(clientsock, recvname[i]);//RCPT TO

	if (returnError(Recvs(clientsock), returnSock) == -1) {
		return -1;
	};
	
	Sends(clientsock, response[5]);//DATA
	if (returnError(Recvs(clientsock), returnSock) == -1) {
		return -1;
	};

	for (int i = 0; i < divnum; i++) {
		Sends(clientsock, message[3+i]);//�ʼ�����
	}


	if (returnError(Recvs(clientsock), returnSock) == -1) {
		return -1;
	};

	Sends(clientsock, response[4]);//quit
	if (returnError(Recvs(clientsock), returnSock) == -1) {
		return -1;
	};

	closesocket(clientsock);
	//WSACleanup();

	return 0;

}

int returnError(char * temp1,SOCKET returnSock) {
	char temp2[2];
	strncpy(temp2, temp1, 1);
	temp2[1] = '\0';
	if (strcmp(temp2, "4") == 0|| strcmp(temp2, "5") == 0) {
		Sends(returnSock, temp1);
		printf("%s\n", temp1);
		return -1;
	}
	else {
		return 0;
	}
}

void printIP(SOCKET socket) {
	SOCKADDR_IN sockAddr1;
	SOCKADDR_IN sockAddr2;
	int iLen1 = sizeof(sockAddr1);
	int iLen2 = sizeof(sockAddr2);
	if (getsockname(socket, (struct sockaddr *)&sockAddr1, &iLen1) == 0) {//�õ����ص�IP��ַ�Ͷ˿ں�
		printf("���� IP��ַ��%s  �˿ںţ�%d\n", inet_ntoa(sockAddr1.sin_addr), ntohs(sockAddr1.sin_port));
	};
	//printf("���� IP��ַ��%s  �˿ںţ�%d\n", inet_ntoa(sockAddr1.sin_addr), sockAddr1.sin_port);
	if (getpeername(socket, (struct sockaddr *)&sockAddr2, &iLen2) == 0) {//�õ�Զ��IP��ַ�Ͷ˿ں�
		printf("Զ�� IP��ַ��%s  �˿ںţ�%d\n", inet_ntoa(sockAddr2.sin_addr), ntohs(sockAddr2.sin_port));
	}
	


}

void initNowtime() {   //��ʼ����ǰʱ��
	char *wday[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
	time_t timep;
	struct tm *p;
	time(&timep);
	p = gmtime(&timep);
	sprintf(nowtime, "%d %d %d %s %d %d %d\0", (1900 + p->tm_year), (1 + p->tm_mon), p->tm_mday, wday[p->tm_wday], (p->tm_hour + 8) % 24, p->tm_min, p->tm_sec);
}

void writeLog(char * str) {   //��д��־�ļ�
	FILE *fp;
	if ((fp = fopen(filename, "a+")) < 0) {
		printf("fopen() error.\n");
		exit(1);
	}
	fprintf(fp, "%s\n", str);
	fclose(fp);
}

void Sends(SOCKET Sock, char* str) {
	if (send(Sock, str, strlen(str), NULL) < 0) {
		printf("send() error.\n");
		exit(1);
	};
	writeLog(str);//���������Ϣ�ɹ�д����־�ļ�
}

char* Recvs(SOCKET Sock) {
	char tBuffer[10000] = { 0 };
	int temp;
	if ((temp = recv(Sock, tBuffer, 10000, NULL))< 0) {
		printf("recv() error1.\n");
		exit(1);
	}
	//printf("%d\n", temp);
	writeLog(tBuffer);
	return tBuffer;
}

int islegal(char ch) {
	if (ch == '.' || ch == '_'||ch=='-' || ch == '!' || ch == '#' || ch == '$' ||
		ch == '%' || ch == '\'' || ch == '*' || ch == '+' || ch == '/' || ch == '='
		|| ch == '?' || ch == '^' || ch == '{' || ch == '|' || ch == '}' || ch == '~') return 1;
	else if (ch >= '0' && ch <= '9') return 1;
	else if (ch >= 'a' && ch <='z') return 1;
	else if (ch >= 'A' && ch <= 'Z') return 1;
	else if (ch == '@') return 1;
	return 0;
}

int afew(char s[], char ch) { // ���ش����м����ַ�ch
	int i = 0, n = 0;
	while (s[i]) {
		if (ch == s[i]) ++n;
		++i;
	}
	return n;
}

int pos(char s[], char ch) {
	int i = 0;
	while (s[i] != ch && s[i]) ++i;
	if (s[i] == '\0') return -1;
	return  i;
}

int Checkmailaddr(char email[101]) 
{
	int i, p, flag = 0;


	flag = 1;
	for (i = 0; email[i] && islegal(email[i]); ++i);
	if (email[i] == '\0' && afew(email, '@') == 1) {
		flag = 1;
		if ((p = pos(email, '.')) > 0) {
			flag = 1;
			if (email[p - 1] != '.' && email[p + 1] != '.') {
				flag = 1;
				p = pos(email, '@');
				if (email[p - 1] != '.' && email[p + 1] != '.')
					flag = 1;
				printf("YES\n");
			}
			else flag = 0;
		}
		else flag = 0;
	}
	else flag = 0;
	if (flag == 0) return -1;

	return 0;

}

