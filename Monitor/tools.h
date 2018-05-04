
/************************************************************************/
/* 此部分主要是调用函数的结构体                                                                     */
/************************************************************************/
#ifndef __FILE_TOOLS_H_VERSION__
#define __FILE_TOOLS_H_VERSION__ 100

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifdef __cplusplus
extern "C" {
#endif
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <string.h>

#ifdef __cplusplus
}; // extern "C"

#include "FileEncrypt.h"

#include <stdarg.h>
#endif



#define FAT_NTC_FCB               0x0502
#define FAT_NTC_DCB               0x0503
#define FAT_NTC_ROOT_DCB          0x0504
#define NTFS_NTC_DCB              0x0703
#define NTFS_NTC_ROOT_DCB         0x0704
#define NTFS_NTC_FCB              0x0705





/************************************************************************/
/*                           定义常量                                 */
/************************************************************************/


//定义通信口名称
#define		SERVER_PORT_NAME	L"\\FileEncryptPort"

//定义通信口最大连接数
#define		SERVER_MAX_COUNT	1



//定义消息码 请求
#define		CODE_OPEN_SYSTEM	0x0001	//打开系统

#define		CODE_CLOSE_SYSTEM	0x0002	//关闭系统

#define		CODE_SEND_STRATEGY	0x0003	//发送策略

#define		CODE_SEND_KEY		0x0004	//发送密码

#define		CODE_IS_RUNNING		0x0005	//查询系统是否运行


//回送

#define		CODE_SUCCESS		0x0006	//操作成功

#define		CODE_UNSUCCESS		0x0007  //操作不成功

#define		CODE_UNKNOW_CODE	0x0008	//不明指令

#define		CODE_RUNNING		0x0009	//系统运行

#define		CODE_CLOSED			0x000a	//系统停止


/************************************************************************/
/*                      定义数据结构                                     */
/************************************************************************/
//消息结构体
typedef struct _MESSAGE_DATA
{
	INT32	code;                 //消息码

	INT32	bufferLen;            //缓冲区长度

	CHAR	buffOffset[1];        //缓冲区开始
} MESSAGE_DATA,*PMESSAGE_DATA;


//消息回送
typedef struct _MESSAGE_BACK
{
	INT32 code;                   //返回码
} MESSAGE_BACK,*PMESSAGE_BACK;





PCHAR  GetCurrentTimeString();


ULONG	GetTime();
 VOID DbgKeLog(PCHAR lpszLog);

//从字符串中构造一个策略表，返回表头
//PTYPE_KEY_PROCESS GetStrategyFromString(CHAR *StrategyString);

//释放一个策略表
void FreeStrategy(PTYPE_KEY_PROCESS head);


//判断进程名是否为该类型的机密进程
BOOLEAN IsSecretProcess(PTYPE_KEY_PROCESS keyWord,CHAR *processName);


/************************************************************************/
/*     进程相关                                                        */
/************************************************************************/
//获取进程名偏移
ULONG 
GetProcessNameOffset(VOID);

//获取进程名称
PCHAR
GetCurrentProcessName(ULONG ProcessNameOffset);



/************************************************************************/
/*                   字符串函数                                             */
/************************************************************************/

//将wchar_t* 转成char*的函数：
void wstr2cstr(const wchar_t *pwstr , char *pcstr, size_t len);

//将char* 转成wchar_t*的实现函数如下：
void cstr2wstr( const char *pcstr,wchar_t *pwstr , size_t len);














#endif // 

























