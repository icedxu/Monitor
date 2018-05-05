///////////////////////////////////////////////////////////////////////////////
///

/// Author(s)        : icedxu
///
/// Purpose          : 文件监控
///
/// Revisions:
///  0000 [2017-05-02] Initial revision.
///
///////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <string.h>
#ifdef __cplusplus
}; // extern "C"
#endif

#include "FileEncrypt.h"
#include "tools.h"

#define PAGEDCODE   code_seg("PAGE")  
#define LOCKEDCODE  code_seg() 
 

/************************************************************************/
/* 全局变量                                                              */
/************************************************************************/
//
//  This is a lookAside list used to allocate our pre-2-post structure.
//
NPAGED_LOOKASIDE_LIST Pre2PostContextList;

//进程名的偏移
ULONG  ProcessNameOffset = 0;

//minifilter 句柄
PFLT_FILTER gFilterHandle;

//客户端句柄，以后有用
PFLT_PORT gClientPort;

//进程链表头
PTYPE_KEY_PROCESS key_word_header;

//全局开关
BOOLEAN IS_SYSTEM_OPEN =FALSE;



//通信端口句柄
PFLT_PORT serverPort=NULL;



#ifdef __cplusplus
extern "C" {
#endif


	////驱动入口
	NTSTATUS DriverEntry(
		IN OUT PDRIVER_OBJECT   DriverObject,
		IN PUNICODE_STRING      RegistryPath
		)
	{
		NTSTATUS status;
		PSECURITY_DESCRIPTOR  sd;
		OBJECT_ATTRIBUTES oa;
		UNICODE_STRING portName=RTL_CONSTANT_STRING(SERVER_PORT_NAME);
			
		KdPrint(("DriverEntry \n"));

		//过滤掉系统自带的一些进程
	//	CHAR StrategyString[]="System;svchost.exe;explorer.exe;vmtoolsd.exe;";
		//key_word_header = GetStrategyFromString(StrategyString);
	
		
	

		//获取进程名称偏移
		ProcessNameOffset=GetProcessNameOffset();

		PsSetCreateProcessNotifyRoutine(MyMiniFilterProcessNotify, FALSE);
		PsSetLoadImageNotifyRoutine(MyMiniFilterLoadImage);//

		//初始化Lookaside对象,不分页
		ExInitializeNPagedLookasideList( &Pre2PostContextList,
			NULL,
			NULL,
			0,
			sizeof(PRE_2_POST_CONTEXT),
			PRE_2_POST_TAG,
			0 );

		//注册
		status=FltRegisterFilter(DriverObject,
								&FilterRegistration,
								&gFilterHandle);
			
		ASSERT(NT_SUCCESS(status));		
		if (NT_SUCCESS(status))
		{
			//启动过滤器
			status=FltStartFiltering(gFilterHandle);
			if(!NT_SUCCESS(status))
			{
				ExDeleteNPagedLookasideList( &Pre2PostContextList );
				FltUnregisterFilter(gFilterHandle);
			}

			//以下与通信相关
			status = FltBuildDefaultSecurityDescriptor(&sd,FLT_PORT_ALL_ACCESS);
			if (!NT_SUCCESS(status))
			{
				////////////DbgPrint("通信端口中申请默认安全级失败\n");
				return status;
			}
			InitializeObjectAttributes(&oa,
										&portName,
										OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,
										NULL,
										sd);
				//注册通信端口
			status = FltCreateCommunicationPort(gFilterHandle,
												&serverPort,
												&oa,
												NULL,
												MyConnectionCallback,
												MyDisconnectCallback,
												MyMessageCallback,
												SERVER_MAX_COUNT
												);

			if (!NT_SUCCESS(status))
			{
				////////////DbgPrint("注册服务器端口失败 \n");
				ExDeleteNPagedLookasideList( &Pre2PostContextList );
				FltUnregisterFilter(gFilterHandle);
			}
				FltFreeSecurityDescriptor( sd );
		} 
		return status;
	}

#ifdef __cplusplus
}; // extern "C"
#endif




///////////////////////////////Create/////////////////////////////////////


FLT_PREOP_CALLBACK_STATUS
CreatePre(
			__inout PFLT_CALLBACK_DATA Data,
			__in PCFLT_RELATED_OBJECTS FltObjects,
			__deref_out_opt PVOID *CompletionContext
			)
{

	return  FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


#pragma  LOCKEDCODE
FLT_POSTOP_CALLBACK_STATUS
CreatePost(
			 __inout PFLT_CALLBACK_DATA Data,
			 __in PCFLT_RELATED_OBJECTS FltObjects,
			 __in PVOID CompletionContext,
			 __in FLT_POST_OPERATION_FLAGS Flags
			 )
{
	FLT_POSTOP_CALLBACK_STATUS retValue = FLT_POSTOP_FINISHED_PROCESSING;
	PSTREAM_HANDLE_CONTEXT streamCtx = NULL;
	NTSTATUS status;
	//检查中断级
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return retValue;
	}
		//下句用来判断此文件操作是创建、打开等
		UCHAR create_options = (UCHAR)((Data->Iopb->Parameters.Create.Options>>24)&0xff);
		if (create_options == FILE_CREATE)
		{ 	
			/*新建文件*/
			STREAM_HANDLE_CONTEXT temCtx;	
				status = GetFileInformation(Data,FltObjects,&temCtx);

				if (NT_SUCCESS(status))
				{
					PCHAR procName=GetCurrentProcessName(ProcessNameOffset);
						//获取系统运行时间，此函数返回值已被处理只返回开机到到现在的秒数，可以放在日志的开头
					ULONG Time = GetTime();
					if (!IsSecretProcess(procName))
					{
						//KdPrint(("%d Newfile进程 = %s,类型=%wZ,卷fu路径=%wZ\n ",Time,procName,&temCtx.fileStyle,&temCtx.ParentDir));

					}
					
					


					/*KdPrint(("文件类型 = %d,文件路径:= %d ", temCtx.fileStyle.Length,temCtx.fileFullPath.Length));
					KdPrint(("所在卷:= %d 父目录 = %d\n", temCtx.fileVolumeName.Length,temCtx.fileName.Length));
					KdPrint(("文件路径:= %wZ , 文件类型 = %wZ", &temCtx.fileFullPath,&temCtx.fileStyle));	
					KdPrint(("所在卷 =%wZ,父目录=%wZ \n ",&temCtx.fileVolumeName,&temCtx.fileName));	*/

				
				} 
		 
		/*		CHAR *lp ;
	
			lp ="nihaonihao \r\n";
			DbgKeLog(lp);*/
			
		}
	return retValue;
}



///////////////////////////////Write/////////////////////////////////////
#pragma  LOCKEDCODE
FLT_PREOP_CALLBACK_STATUS
	WritePre(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
	)
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;

	//检查中断级
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return retValue; 
	}

	
	return retValue;
}


#pragma  LOCKEDCODE
FLT_POSTOP_CALLBACK_STATUS
	WritePost(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
	)
{
	PPRE_2_POST_CONTEXT p2pCtx = (PPRE_2_POST_CONTEXT)CompletionContext;
	UNREFERENCED_PARAMETER( FltObjects );
	UNREFERENCED_PARAMETER( Flags );
	NTSTATUS status;
	STREAM_HANDLE_CONTEXT temCtx;	
	//检查中断级
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	status = GetFileInformation(Data,FltObjects,&temCtx);
	
if (NT_SUCCESS(status))
		{
			//PCHAR procName=GetCurrentProcessName(ProcessNameOffset);
			//PEPROCESS  p = FltGetRequestorProcess(Data);
			ULONG ProcessId = FltGetRequestorProcessId(Data);  
			ULONG ThreadId = (ULONG)PsGetThreadId(Data->Thread);  
			//EnumThread(p);
			EnumProcess(ThreadId);
			KdPrint((" ThreadId = %u \n",ThreadId));
			/*ULONG Time = GetTime();
			if (!IsSecretProcess(procName))
			{
			

			KdPrint((" procName= %s PID =%u,TID = %u\n",procName,ThreadId,ProcessId));
			KdPrint(("%d Write 进程 = %s,类型=%wZ,卷路径=%wZ\n ",Time,procName,&temCtx.fileStyle,&temCtx.fileFullPath));


			}
			*/
					/*KdPrint(("文件类型 = %d,文件路径:= %d ", temCtx.fileStyle.Length,temCtx.fileFullPath.Length));
					KdPrint(("所在卷:= %d 父目录 = %d\n", temCtx.fileVolumeName.Length,temCtx.fileName.Length));
					KdPrint(("文件路径:= %wZ , 文件类型 = %wZ", &temCtx.fileFullPath,&temCtx.fileStyle));	
					KdPrint(("所在卷 =%wZ,父目录=%wZ \n ",&temCtx.fileVolumeName,&temCtx.fileName));	*/

		} 

	return FLT_POSTOP_FINISHED_PROCESSING;
}








////////////////////////////////SetInformation//////////////////////////////////
/****
 *在这个IRP中可判断重命名与删除操作
 **/
#pragma  LOCKEDCODE
FLT_PREOP_CALLBACK_STATUS
SetInformationPre(
					__inout PFLT_CALLBACK_DATA Data,
					__in PCFLT_RELATED_OBJECTS FltObjects,
					__deref_out_opt PVOID *CompletionContext
					)
{
	FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

	STREAM_HANDLE_CONTEXT temCtx;
	NTSTATUS status;

	//检查中断级
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	//获取文件信息
	status = GetFileInformation(Data,FltObjects,&temCtx);
	if (NT_SUCCESS(status))
		{
			if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation)
			{
				PCHAR procName=GetCurrentProcessName(ProcessNameOffset);
				if (!IsSecretProcess(procName))
				{
					//获取系统运行时间，此函数返回值已被处理只返回开机到到现在的秒数，可以放在日志的开头
					ULONG Time = GetTime();
				   KdPrint(("%d Delete进程 = %s,类型=%wZ,卷路径=%wZ\n ",Time,procName,&temCtx.fileStyle,&temCtx.fileVolumeName));
				}
		}


			if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation)
			{
				PCHAR procName=GetCurrentProcessName(ProcessNameOffset);
				if (!IsSecretProcess(procName))
				{
					//获取系统运行时间，此函数返回值已被处理只返回开机到到现在的秒数，可以放在日志的开头
				  ULONG Time = GetTime();
				  KdPrint(("%d Rename进程 = %s,类型=%wZ,卷路径=%wZ\n ",Time,procName,&temCtx.fileStyle,&temCtx.fileVolumeName));
				}
			}

					/*KdPrint(("文件类型 = %d,文件路径:= %d ", temCtx.fileStyle.Length,temCtx.fileFullPath.Length));
					KdPrint(("所在卷:= %d 父目录 = %d\n", temCtx.fileVolumeName.Length,temCtx.fileName.Length));
					KdPrint(("文件路径:= %wZ , 文件类型 = %wZ", &temCtx.fileFullPath,&temCtx.fileStyle));	
					KdPrint(("所在卷 =%wZ,父目录=%wZ \n ",&temCtx.fileVolumeName,&temCtx.fileName));	*/

				
			
		} 

	return retValue;
}

#pragma  LOCKEDCODE
FLT_POSTOP_CALLBACK_STATUS
SetInformationPost(
					 __inout PFLT_CALLBACK_DATA Data,
					 __in PCFLT_RELATED_OBJECTS FltObjects,
					 __in PVOID CompletionContext,
					 __in FLT_POST_OPERATION_FLAGS Flags
					 )
{

	return FLT_POSTOP_FINISHED_PROCESSING;
}


///////////////////////////卸载函数/////////////////////////////////
#pragma  LOCKEDCODE
NTSTATUS
FilterUnload (
			  __in FLT_FILTER_UNLOAD_FLAGS Flags
			  )
{

	UNREFERENCED_PARAMETER( Flags );
	//FreeStrategy(key_word_header);	
	FltCloseCommunicationPort(serverPort);

	PsSetCreateProcessNotifyRoutine(MyMiniFilterProcessNotify, TRUE);
	PsRemoveLoadImageNotifyRoutine(MyMiniFilterLoadImage);
	ExDeleteNPagedLookasideList( &Pre2PostContextList );
	FltUnregisterFilter( gFilterHandle );
	return STATUS_SUCCESS;
}
















//////////ignore
#pragma  LOCKEDCODE
NTSTATUS
InstanceSetup (
			   __in PCFLT_RELATED_OBJECTS FltObjects,
			   __in FLT_INSTANCE_SETUP_FLAGS Flags,
			   __in DEVICE_TYPE VolumeDeviceType,
			   __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
			   )
{
	UNREFERENCED_PARAMETER( Flags );
	UNREFERENCED_PARAMETER( VolumeDeviceType );
	UNREFERENCED_PARAMETER( VolumeFilesystemType );
	////KdPrind(("InstanceSetup\n"));
	return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
#pragma  LOCKEDCODE
VOID 
CleanupStreamHandleContext(
						   __in PFLT_CONTEXT Context,
						   __in FLT_CONTEXT_TYPE ContextType				 
						   )
{

	UNREFERENCED_PARAMETER( ContextType );

	switch(ContextType)
	{
	case  FLT_STREAMHANDLE_CONTEXT:
		{
			////KdPrind(("进入FLT_STREAMHANDLE_CONTEXT \n"));
			break;

		}
	case FLT_VOLUME_CONTEXT:
		{
			PVOLUME_CONTEXT VolCtx =(PVOLUME_CONTEXT)Context;
			////KdPrind(("进入FLT_VOLUME_CONTEXT \n"));
			if (VolCtx->Name.Buffer != NULL) 
			{
				ExFreePool(VolCtx->Name.Buffer);
				VolCtx->Name.Buffer = NULL;
			}
			break;
		}

	case FLT_INSTANCE_CONTEXT:
		{
			////KdPrind(("进入 FLT_INSTANCE_CONTEXT"));
			break;
		}
			
	case FLT_FILE_CONTEXT:
		{
		//	//KdPrind(("进入 FLT_FILE_CONTEXT"));
			break;
			}
			
	case FLT_STREAM_CONTEXT:
		{
			////KdPrind(("进入 FLT_STREAM_CONTEXT"));
			break;
			}
		
	case FLT_TRANSACTION_CONTEXT:
		{
			////KdPrind(("进入 FLT_TRANSACTION_CONTEXT"));
			break;
			}
			
	case FLT_CONTEXT_END:
		{
			////KdPrind(("进入 FLT_CONTEXT_END  "));
			break;
		}
	default:
		{
			////KdPrind(("进入default\n"));
			break;
		}
	}


	////KdPrind(("CleanupStreamHandleContext离开\n"));
}

//////////////////////////////////////////////////////////////////////////

NTSTATUS
InstanceQueryTeardown (
					   __in PCFLT_RELATED_OBJECTS FltObjects,
					   __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
					   )

{

	UNREFERENCED_PARAMETER( FltObjects );
	UNREFERENCED_PARAMETER( Flags );
	//检查中断级
	PAGED_CODE();	
	//KdPrind(("进入InstanceQueryTeardown \n"));
	return STATUS_SUCCESS;
}

/************************************************************************/
/*                    通信口回调函数                                    */
/************************************************************************/

//连接回调
NTSTATUS
MyConnectionCallback(
					 __in PFLT_PORT ClientPort,
					 __in_opt PVOID ServerPortCookie,
					 __in_bcount_opt(SizeOfContext) PVOID ConnectionContext,
					 __in ULONG SizeOfContext,
					 __deref_out_opt PVOID *ConnectionPortCookie
					 )
{
	PAGED_CODE();
	UNREFERENCED_PARAMETER( ServerPortCookie );
	UNREFERENCED_PARAMETER( ConnectionContext );
	UNREFERENCED_PARAMETER( SizeOfContext);
	UNREFERENCED_PARAMETER( ConnectionPortCookie );
	ASSERT(gClientPort == NULL);
	//KdPrind(("Connect\n"));
	gClientPort = ClientPort; //保存供以后使用
	return STATUS_SUCCESS;
}


//关闭回调
VOID
MyDisconnectCallback (
					  __in_opt PVOID ConnectionCookie
					  )
{
	//KdPrind(("MyDisconnectCallback"));
	PAGED_CODE();
	UNREFERENCED_PARAMETER(ConnectionCookie);
	//KdPrind(("Disconnect\n"));
	//关闭通信连接
	FltCloseClientPort(gFilterHandle , &gClientPort);
}

#pragma  LOCKEDCODE
//消息回调
NTSTATUS
MyMessageCallback (
				   __in_opt PVOID PortCookie,
				   __in_bcount_opt(InputBufferLength) PVOID InputBuffer,
				   __in ULONG InputBufferLength,
				   __out_bcount_part_opt(OutputBufferLength,*ReturnOutputBufferLength) PVOID OutputBuffer,
				   __in ULONG OutputBufferLength,
				   __out PULONG ReturnOutputBufferLength
				   )
{

	//检查缓冲区长度
	if (InputBufferLength<sizeof(MESSAGE_DATA)||OutputBufferLength<sizeof(MESSAGE_BACK))
	{
		////////////DbgPrint("UNSUCCESSFUL\n");
		return STATUS_UNSUCCESSFUL;
	}

	PMESSAGE_DATA msg=(PMESSAGE_DATA)InputBuffer;
	PMESSAGE_BACK back=(PMESSAGE_BACK)OutputBuffer;
	*ReturnOutputBufferLength=sizeof(MESSAGE_BACK);
	//执行指令
	switch(msg->code)
	{
	case CODE_OPEN_SYSTEM:	//打开系统
		{

			IS_SYSTEM_OPEN=TRUE;
			back->code=CODE_SUCCESS;
			////////////DbgPrint("open system \n");
			break;
		}
	case CODE_CLOSE_SYSTEM:	//关闭系统		  
		{
			IS_SYSTEM_OPEN=FALSE;
			back->code=CODE_SUCCESS;
			////////////DbgPrint("close system \n");
			break;
		}

	case CODE_IS_RUNNING://查询状态
		{
			if (IS_SYSTEM_OPEN)
			{
				back->code=CODE_RUNNING;
			}
			else
			{
				back->code=CODE_CLOSED;
			}
			break;
		}
	case CODE_SEND_STRATEGY://发送策略表
		{
			////////////DbgPrint("send strategy \n");

			CHAR *str=msg->buffOffset;

			IS_SYSTEM_OPEN=FALSE;
			//释放原来策略表
			if(key_word_header!=NULL)
			{
				FreeStrategy(key_word_header);
			}

			//key_word_header=GetStrategyFromString(str);

			
			back->code=CODE_SUCCESS;
			//////////////DbgPrint("send strategy is %s",str);
			break;
		}
	
	default:
		{
			////////////DbgPrint("UNSUCCESS\n");
			back->code=CODE_UNKNOW_CODE;
			break;
		}

	}

	return STATUS_SUCCESS;

}



VOID 
	MyMiniFilterLoadImage( __in_opt PUNICODE_STRING FullImageName, __in HANDLE ProcessId, __in PIMAGE_INFO ImageInfo )
{
	UNREFERENCED_PARAMETER(ImageInfo);

	if (FullImageName)
	{
		DbgPrint("MyMiniFilterLoadImage, image name: %wZ, pid: %d\n", FullImageName, ProcessId);
	}
	else
		DbgPrint("MyMiniFilterLoadImage, image name: null, pid: %d\n", ProcessId);
}




VOID
	MyMiniFilterProcessNotify(
	IN HANDLE  ParentId,
	IN HANDLE  ProcessId,
	IN BOOLEAN  Create
	)
{
	DbgPrint("MyMiniFilterProcessNotify, pid: %d, tid: %d, create: %d\n", ParentId, ProcessId, Create);
}

//枚举指定进程的线程
VOID EnumThread(PEPROCESS Process)
{
	ULONG i = 0, c = 0;
	PETHREAD ethrd = NULL;
	PEPROCESS eproc = NULL;
	for (i = 4; i<262144; i = i + 4)
	{
		ethrd = LookupThread((HANDLE)i);
		if (ethrd != NULL)
		{
			//获得线程所属进程
			eproc = IoThreadToProcess(ethrd);
			if (eproc == Process)
			{
				//打印出 ETHREAD 和 TID
				DbgPrint("ETHREAD=%p, TID=%ld\n",
					ethrd,
					(ULONG)PsGetThreadId(ethrd));
			}
			ObDereferenceObject(ethrd);
		}
	}
}


//根据线程 ID 返回线程 ETHREAD，失败返回 NULL
PETHREAD LookupThread(HANDLE Tid)
{
	PETHREAD ethread;
	if (NT_SUCCESS(PsLookupThreadByThreadId(Tid, &ethread)))
		return ethread;
	else
		return NULL;
}