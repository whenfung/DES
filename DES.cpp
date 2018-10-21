#include <stdlib.h>
#include <stdio.h>
#include "DES_tables.h"

static bool SubKey[16][48]= {0}; //子密钥序列

void BitsCopy(bool *BitIn,bool *BitOut,int Len) {  //BitOut 就是IP置换后的信息 
//数组复制
	int i=0;
	for(i=0; i<Len; i++) {
		BitOut[i]=BitIn[i];
	}
}
void TablePermute(bool *BitIn,bool *BitOut,const char *Table,int Num) {  //IP置换 
//原来的数据按对应的表上的位置进行放置
	int i=0;
	static bool temp[256]= {0};
	for(i=0; i<Num; i++) {
		temp[i]=BitIn[Table[i]-1];
	}
	BitsCopy(temp,BitOut,Num);
}

void ByteToBit(char *ByteIn,bool *BitOut,int Num) {
//将字节转为Byte
	int i=0;
	for(i=0; i<Num; i++) {
		BitOut[i]=(ByteIn[i/8]>>(i%8))&0x01;  //利用与0x01做与操作进行掩码后得到的0或1 
	}
}
void LoopMove(bool *BitIn,int Len,int Num) {    //循环左移操作 
//移位操作，注意需将左边的那1或2位移到最右边
	static bool temp[256]= {0};
	BitsCopy(BitIn,temp,Num);
	BitsCopy(BitIn+Num,BitIn,Len-Num);
	BitsCopy(temp,BitIn+Len-Num,Num);
}
void Getsubkey(char KeyIn[8]) {             //生成子密钥 
//通过密钥获得子密钥
	int i=0;
	static bool KeyBit[64]= {0};              
	static bool *KiL=&KeyBit[0],*KiR=&KeyBit[28];
	ByteToBit(KeyIn,KeyBit,64);                    //子密钥转为bits 
	TablePermute(KeyBit,KeyBit,Subkey_Table,56);   //子密钥压缩，舍弃每一个字符的第八位 
	for(i=0; i<16; i++) {                          //子密钥的高28位和低28位分别进行循环左移，左移次数看对应的Move_table表 
		LoopMove(KiL,28,Move_Table[i]);
		LoopMove(KiR,28,Move_Table[i]);
		TablePermute(KeyBit,SubKey[i],Compress_Table,48); //将得到的第i个子密钥放到subKey[i]中 
	}
}

void Xor(bool *Bit1,bool *Bit2,int Num) {
// 按位异或，存储结果在第一个里
	int i=0;
	for(i=0; i<Num; i++) {
		Bit1[i]=Bit1[i]^Bit2[i];
	}
}
void S_Change(bool BitIn[48],bool BitOut[32]) {
// S盒变换，将48位的处理结果压缩成32位 
	int i,X,Y;
	for(i=0,Y=0,X=0; i<8; i++,BitIn+=6,BitOut+=4) {
		Y=(BitIn[0]<<1)+BitIn[5];                            //1和6位决定行数
		X=(BitIn[1]<<3)+(BitIn[2]<<2)+(BitIn[3]<<1)+BitIn[4];//2345决定列数
		ByteToBit(&S_Box[i][Y][X],BitOut,4);
	}
}
void DES_1turn(bool BitIn[32],bool BitKi[48]) {  //右半段拓展后与子密钥进行异或 
	static bool MiR[48]= {0};         
	TablePermute(BitIn,MiR,Ex_Table,48);        //扩展为48位
	Xor(MiR,BitKi,48);                          //异或操作 
	S_Change(MiR,BitIn);                        //S盒代换压缩 
	TablePermute(BitIn,BitIn,P_Box,32);         //P置换，左半边和右半边的处理结果进行异或，然后左右交换，一轮就算完了 
}

void BitToHex(bool *BitIn,char *ByteOut,int Num) {
//Bit转Hex
	int i=0;
	for(i=0; i<Num/4; i++) {
		ByteOut[i]=0;
	}
	for(i=0; i<Num/4; i++) {             //利用二进制算术运算得到的数字再转化为相应的char型 
		ByteOut[i] = BitIn[i*4]+(BitIn[i*4+1]<<1)
		             +(BitIn[i*4+2]<<2)+(BitIn[i*4+3]<<3);
		if((ByteOut[i])>9) {
			ByteOut[i]=ByteOut[i]+'7';  //这是由于ASCII码 的数字和字母之间由六个符号的原因 
		} else {
			ByteOut[i]=ByteOut[i]+'0';
		}
	}
}
void BitToByte(bool *ByteIn,char *BitOut,int Num) {
//每8次左移一位异或
	int i=0;
	for(i=0; i<(Num/8); i++) {
		BitOut[i]=0;
	}
	for(i=0; i<Num; i++) {
		BitOut[i/8]|=ByteIn[i]<<(i%8);
	}
}
void HexToBit(char *ByteIn,bool *BitOut,int Num) {
//Hex转Bit
	int i=0;
	for(i=0; i<Num; i++) {
		if((ByteIn[i/4])>'9') {
			BitOut[i]=((ByteIn[i/4]-'7')>>(i%4))&0x01;    //又是掩码原理 
		} else {
			BitOut[i]=((ByteIn[i/4]-'0')>>(i%4))&0x01;     
		}
	}
}
void DES_Cry(char MesIn[8],char MesOut[8]) {
//执行DES加密函数
	int i=0;
	static bool MesBit[64]= {0};                  //信息 
	static bool Temp[32]= {0};                    //中间变量 
	static bool *MiL=&MesBit[0],*MiR=&MesBit[32]; //前后32位
	ByteToBit(MesIn,MesBit,64);                   //char转bit到MesBit中 
	TablePermute(MesBit,MesBit,IP_Table,64);      //IP置换，对信息进行错位 
	for(i=0; i<16; i++) {                         //16轮迭代
		BitsCopy(MiR,Temp,32);                    //右半边复制到临时变量temp 
		DES_1turn(MiR,SubKey[i]);                 //右半边拓展和子密钥进行异或然后压缩 
		Xor(MiR,MiL,32);                          //左右异或放到右边 
		BitsCopy(Temp,MiL,32);                    //一开始的右边数据放到左边 
	}
	TablePermute(MesBit,MesBit,IPre_Table,64);    //IP逆置换 
	BitToHex(MesBit,MesOut,64);                   //以16进制输出密文 
}

void DES_Dec(char MesIn[8],char MesOut[8]) {
//DES解密，加密的逆过程 
	int i=0;
	static bool MesBit[64]= {0};
	static bool Temp[32]= {0};
	static bool *MiL=&MesBit[0],*MiR=&MesBit[32];
	HexToBit(MesIn,MesBit,64);                     //16进制密文转二进制 
	TablePermute(MesBit,MesBit,IP_Table,64);       //IP置换 
	for(i=15; i>=0; i--) {                         //逆循环 
		BitsCopy(MiL,Temp,32);                     //R(i-1) = Li, L15是密文的前半段，可以逆推 
		DES_1turn(MiL,SubKey[i]);                  //Ri = L(i-1)^f(R(i-1), K(i-1))   K(i-1)是子密钥，R15已知，根据 a = b ^ c 得 b = a^c,可以求L(i-1) 
		Xor(MiL,MiR,32);                           //左右异或得到右边的原始信息放回左边 
		BitsCopy(Temp,MiR,32);                     //中间变量放到右边 
	}
	TablePermute(MesBit,MesBit,IPre_Table,64);     //IP逆置换 
	BitToByte(MesBit,MesOut,64);                   //二进制转char 
}

int main() {
	int i=0;
	char MesHex[16]= {0};     //存放密文
	char MyKey[8]= {0};       //初始密钥
	char YourKey[8]= {0};     //解密密钥
	char MyMessage[8]= {0};   //明文
	printf("Please input your Message(Max 64 bit):\n");
	gets(MyMessage);//明文
	printf("Please input your Secret Key(64 bit):\n");
	gets(MyKey);//密钥
	Getsubkey(MyKey);            //生成子密钥放在主函数执行 
 	DES_Cry(MyMessage,MesHex);   //加密过程 
	printf("Your Message is Encrypted As:\n");
	for(i=0; i<16; i++) {
		printf("%c ",MesHex[i]);
	}
	printf("\n");
	printf("Please input your Secret Key to Deciphering:\n");
	gets(YourKey);//get密钥
	Getsubkey(YourKey);   //生成子密钥 
	DES_Dec(MesHex,MyMessage);  //解密过程 
	printf("Deciphering Over !!:\n");
	for(i=0; i<8; i++) {
		printf("%c ",MyMessage[i]);
	}
	printf("\n");
	system("pause");
}
