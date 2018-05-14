
#ifndef __FILE_ENCRYPT_H_VERSION__
#define __FILE_ENCRYPT_H_VERSION__ 100

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif


#include "drvcommon.h"
#include "drvversion.h"
#include "ntstrsafe.h"



/*************************************************************************
    Pool Tags
*************************************************************************/

#define BUFFER_SWAP_TAG     'bdBS'
#define CONTEXT_TAG         'xcBS'
#define NAME_TAG            'mnBS'
#define PRE_2_POST_TAG      'LASI'
#define STREAM_HANDLE_CONTEXT_TAG  'shBS'



#define PBUFFER_TAG  'BUF'
#define LENGTH_READ  40



//minifilter 句柄
extern  PFLT_FILTER gFilterHandle;
extern  HANDLE  handle;
//客户端句柄，以后有用
extern  PFLT_PORT gClientPort;

//同步事件对象  
extern PRKEVENT g_pEventObject;  
//句柄信息  
extern  OBJECT_HANDLE_INFORMATION g_ObjectHandleInfo;  


extern BOOLEAN EXIT;




extern LIST_ENTRY HidePathListHeader;
extern KSPIN_LOCK HidePathListLock;
#define _CMD_PATH 256


typedef struct _HIDE_PATH_LIST
{
	LIST_ENTRY listNode;
	CHAR xxPath[_CMD_PATH];
}LOG_LIST,*PLOG_LIST;




/*************************************************************************
    Local structures
*************************************************************************/

/************************************************************************/
/* 加密策略表结构定义                                                     */
/************************************************************************/
//定义进程信息链表
#define PROCESS_NAME_LEN      32
typedef struct _PROCESS_INFO
{
	CHAR processName[PROCESS_NAME_LEN];//进程名称

	_PROCESS_INFO *next;//下一个节点

} PROCESS_INFO,*PPROCESS_INFO;


//定义类型关键字链表结构
#define TYPE_KEY_WORD_LEN      32
typedef struct _TYPE_KEY_PROCESS
{
	PPROCESS_INFO processInfo;//匹配进程

	_TYPE_KEY_PROCESS *next;//下一个节点

} TYPE_KEY_PROCESS,*PTYPE_KEY_PROCESS;





/************************************************************************/
/* 这是一个上下文结构，用于将状态从预操作到后操作                            */
/************************************************************************/

typedef struct _PRE_2_POST_CONTEXT {

	BOOLEAN IS_DECONGD; 
    PVOID   SwappedBuffer;  //将我们分配的缓冲区地址传递给Post函数以便于释放

} PRE_2_POST_CONTEXT, *PPRE_2_POST_CONTEXT;



//定义流上下文,判断文件头信息
typedef struct _STREAM_HEAD
{
	FILE_STANDARD_INFORMATION fileInfo;//文件信息

	CHAR  fileHead[40];//文件头

	BOOLEAN isRead;//文件是否被读过

} STREAM_HEAD,*PSTREAM_HEAD;














//定义流上下文，获取哪个进程操作了哪个文件（路径和类型）
typedef struct _STREAM_HANDLE_CONTEXT
{
	//FILE_STANDARD_INFORMATION fileInfo;//文件信息

	UNICODE_STRING  ParentDir;  //文件名

	UNICODE_STRING  fileFullPath ;   //完整文件路径

	UNICODE_STRING  fileVolumeName; //文件所在的卷名

	UNICODE_STRING  fileStyle; //文件类型 

} STREAM_HANDLE_CONTEXT,*PSTREAM_HANDLE_CONTEXT;


//声明 API
extern"C" __declspec(dllimport)UCHAR*PsGetProcessImageFileName(IN PEPROCESS Process); 
extern"C" __declspec(dllimport)HANDLE PsGetProcessInheritedFromUniqueProcessId(IN PEPROCESS Process); 



//根据进程 ID 返回进程 EPROCESS，失败返回 NULL
PEPROCESS LookupProcess(HANDLE Pid);
VOID EnumProcess(ULONG);

/************************************************************************/
/*                    通信口回调函数                                      */
/************************************************************************/

//枚举指定进程的线程
VOID EnumThread(PEPROCESS Process);
PETHREAD LookupThread(HANDLE Tid);


VOID 
	MyMiniFilterLoadImage( 
	__in_opt PUNICODE_STRING FullImageName,
	__in HANDLE ProcessId,
	__in PIMAGE_INFO ImageInfo );


VOID
	MyMiniFilterProcessNotify(
	IN HANDLE  ParentId,
	IN HANDLE  ProcessId,
	IN BOOLEAN  Create
	);








//连接回调
NTSTATUS
	MyConnectionCallback(
	__in PFLT_PORT ClientPort,
	__in_opt PVOID ServerPortCookie,
	__in_bcount_opt(SizeOfContext) PVOID ConnectionContext,
	__in ULONG SizeOfContext,
	__deref_out_opt PVOID *ConnectionPortCookie
	);

//关闭回调
VOID
	MyDisconnectCallback (
	__in_opt PVOID ConnectionCookie
	);

//消息回调
NTSTATUS
	MyMessageCallback (
	__in_opt PVOID PortCookie,
	__in_bcount_opt(InputBufferLength) PVOID InputBuffer,
	__in ULONG InputBufferLength,
	__out_bcount_part_opt(OutputBufferLength,*ReturnOutputBufferLength) PVOID OutputBuffer,
	__in ULONG OutputBufferLength,
	__out PULONG ReturnOutputBufferLength
	);

/*************************************************************************
Prototypes
*************************************************************************/

NTSTATUS
	InstanceSetup (
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_INSTANCE_SETUP_FLAGS Flags,
	__in DEVICE_TYPE VolumeDeviceType,
	__in FLT_FILESYSTEM_TYPE VolumeFilesystemType
	);

VOID
	CleanupVolumeContext(
	__in PFLT_CONTEXT Context,
	__in FLT_CONTEXT_TYPE ContextType
	);

VOID
	CleanupStreamHandleContext(
	__in PFLT_CONTEXT Context,
	__in FLT_CONTEXT_TYPE ContextType
	);

NTSTATUS
	InstanceQueryTeardown (
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
	);


/************************************************************************/
/*        回调函数                                                       */
/************************************************************************/
///IRP_MJ_CREATE
FLT_PREOP_CALLBACK_STATUS
	CreatePre(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS
	CreatePost(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
	);


FLT_POSTOP_CALLBACK_STATUS
	ReadPost(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
	);



/////IRP_MJ_WRITE
FLT_PREOP_CALLBACK_STATUS
	WritePre(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
	);


FLT_POSTOP_CALLBACK_STATUS
	WritePost(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
	);





/////SetInformation
FLT_PREOP_CALLBACK_STATUS
	SetInformationPre(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS
	SetInformationPost(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
	);


NTSTATUS
	FilterUnload (
	__in FLT_FILTER_UNLOAD_FLAGS Flags
	);


NTSTATUS GetFileInformation(__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__inout PSTREAM_HANDLE_CONTEXT ctx);




CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE,
	0,
	NULL,         //
	CreatePost 
	},
	


	//{ IRP_MJ_WRITE,
	//0,
	//NULL,
	//WritePost
	//},

/*
	{ IRP_MJ_SET_INFORMATION,   
	0,
	SetInformationPre,
	SetInformationPost },*/

	{ IRP_MJ_OPERATION_END }
};


//

//
CONST FLT_CONTEXT_REGISTRATION ContextNotifications[] = {

	{ FLT_STREAMHANDLE_CONTEXT,
	0,
	CleanupStreamHandleContext,
	sizeof(STREAM_HEAD),
	STREAM_HANDLE_CONTEXT_TAG },

	{ FLT_CONTEXT_END }
};




CONST FLT_REGISTRATION FilterRegistration = {

	sizeof( FLT_REGISTRATION ),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags

	ContextNotifications,			    //  Context
	Callbacks,                          //  Operation callbacks

	FilterUnload,                       //  MiniFilterUnload

	InstanceSetup,						//  InstanceSetup
	InstanceQueryTeardown,				//  InstanceQueryTeardown
	NULL,                               //  InstanceTeardownStart
	NULL,                               //  InstanceTeardownComplete

	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent

};

#endif 

































