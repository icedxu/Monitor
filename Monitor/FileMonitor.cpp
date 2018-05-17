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
//PFLT_FILTER gFilterHandle;

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

		InitializeListHead(&HidePathListHeader);
		//KeInitializeSpinLock(&HidePathListLock);


	


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
			StartThread();

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
	__try{
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
					PEPROCESS  p = FltGetRequestorProcess(Data);
					ULONG ProcessId = FltGetRequestorProcessId(Data);  
					ULONG ThreadId = (ULONG)PsGetThreadId(Data->Thread); 

					UINT32 Pid = 0 , PPid = 0;
					EnumProcess(ProcessId,&Pid,&PPid);
					//KdPrint(("Pid = %d,PPid = %d \n",Pid,PPid));

					//获取系统运行时间，此函数返回值已被处理只返回开机到到现在的秒数，可以放在日志的开头
			
					//	KdPrint((" ThreadId = %u \n",ThreadId));
					ULONG Time = GetTime();
					CHAR T[100]={0},PID[100]={0},PPID[100] ={0}  ;

					IntegerToChar(Time,T);
					IntegerToChar(PPid,PPID);
					IntegerToChar(Pid,PID);
					//KdPrint(("%s \n",T));
					//KdPrint(("PPID = %s,PID = %s \n",PPID,PID));

					CHAR FileName[260] ={0}; 

					NPUnicodeStringToChar(&temCtx.fileVolumeName, FileName,temCtx.fileVolumeName.Length);
					//KdPrint((" FileName = %s",FileName));
					//T=0;OP=1;C=test.exe;  PID=123;PPID=321;P=\\Device\\HarddiskVolume1\\test;S=15
					//CHAR STR[260] = {"T="};

						CHAR STR[260] = "XXX;";

					if (!IsSecretProcess(procName))
					{
						/*strcat(STR,T);strcat(STR,";OP=1;C="); 
						strcat(STR,procName);strcat(STR,";PID=");
						strcat(STR,PID);strcat(STR,";PPID="); strcat(STR,PPID);strcat(STR,";P=");
						strcat(STR,FileName);strcat(STR,";S="); strcat(STR,"1555\r\n");*/

						strcat(STR,T);strcat(STR,";1;"); 
						strcat(STR,procName);strcat(STR,";");
						strcat(STR,PID);strcat(STR,";"); strcat(STR,PPID);strcat(STR,";");
						strcat(STR,FileName);strcat(STR,"\r\n");
						

						PLOG_LIST pathListNode ,pathList;
						pathListNode = (PLOG_LIST)ExAllocatePool(NonPagedPool,sizeof(LOG_LIST));
						if (pathListNode == NULL)
						{
							KdPrint(("队列申请失败  \n"));  
						}
						//wcscpy(pathListNode->xxPath,pszDest);
						RtlCopyMemory(pathListNode->xxPath,STR,strlen(STR));
						InsertTailList(&HidePathListHeader,&pathListNode->listNode);//插入队尾

					}

				

					/*KdPrint(("文件类型 = %d,文件路径:= %d ", temCtx.fileStyle.Length,temCtx.fileFullPath.Length));
					KdPrint(("所在卷:= %d 父目录 = %d\n", temCtx.fileVolumeName.Length,temCtx.fileName.Length));
					KdPrint(("文件路径:= %wZ , 文件类型 = %wZ", &temCtx.fileFullPath,&temCtx.fileStyle));	
					KdPrint(("所在卷 =%wZ,父目录=%wZ \n ",&temCtx.fileVolumeName,&temCtx.fileName));	*/

				
				} 
			
		}
	}	
	__except(EXCEPTION_EXECUTE_HANDLER)
	{

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
	PCHAR procName=GetCurrentProcessName(ProcessNameOffset);
	//PEPROCESS  p = FltGetRequestorProcess(Data);
	//ULONG ThreadId = (ULONG)PsGetThreadId(Data->Thread); 

	ULONG ProcessId = FltGetRequestorProcessId(Data);  
	UINT32 Pid = 0 , PPid = 0;
	EnumProcess(ProcessId,&Pid,&PPid);
	KdPrint(("Pid = %d,PPid = %d \n",Pid,PPid));



	
	

	
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
	__try{

	status = GetFileInformation(Data,FltObjects,&temCtx);
	
if (NT_SUCCESS(status))
		{
			PCHAR procName=GetCurrentProcessName(ProcessNameOffset);
			PEPROCESS  p = FltGetRequestorProcess(Data);
			ULONG ProcessId = FltGetRequestorProcessId(Data);  
			ULONG ThreadId = (ULONG)PsGetThreadId(Data->Thread);  

			
			UINT32 Pid = 0 , PPid = 0;
			EnumProcess(ProcessId,&Pid,&PPid);

			ULONG Time = GetTime();
			CHAR T[100]={0},PID[100]={0},PPID[100] ={0}  ;

			IntegerToChar(Time,T);
		    IntegerToChar(PPid,PPID);
		    IntegerToChar(Pid,PID);
			//KdPrint(("%s \n",T));
		   // KdPrint(("PPID = %s,PID = %s \n",PPID,PID));

	    	CHAR FileName[260] ={0}; 

			NPUnicodeStringToChar(&temCtx.fileVolumeName, FileName,temCtx.fileVolumeName.Length);
			//KdPrint((" FileName = %s",FileName));
			//T=0;OP=1;C=test.exe;  PID=123;PPID=321;P=\\Device\\HarddiskVolume1\\test;S=15
			//CHAR STR[260] = {"T="};
			CHAR STR[260] = "XXX;";



			if (!IsSecretProcess(procName))
			{

				/*	strcat(STR,T);strcat(STR,";OP=4;C="); strcat(STR,procName);strcat(STR,";PID=");
				strcat(STR,PID);strcat(STR,";PPID="); strcat(STR,PPID);strcat(STR,";P=");
				strcat(STR,FileName);strcat(STR,";S="); strcat(STR,"1555\r\n");*/
				//KdPrint(("%s",STR));


				strcat(STR,T);strcat(STR,";4;"); 
				strcat(STR,procName);strcat(STR,";");
				strcat(STR,PID);strcat(STR,";"); strcat(STR,PPID);strcat(STR,";");
				strcat(STR,FileName);strcat(STR,"\r\n"); 


				PLOG_LIST pathListNode ,pathList;
				pathListNode = (PLOG_LIST)ExAllocatePool(NonPagedPool,sizeof(LOG_LIST));
				if (pathListNode == NULL)
				{
					KdPrint(("队列申请失败  \n"));  
				}
				//wcscpy(pathListNode->xxPath,pszDest);
				RtlCopyMemory(pathListNode->xxPath,STR,strlen(STR));
				InsertTailList(&HidePathListHeader,&pathListNode->listNode);//插入队尾



			}
			
					//KdPrint(("文件类型 = %d,文件路径:= %d ", temCtx.fileStyle.Length,temCtx.fileFullPath.Length));
					//KdPrint(("所在卷:= %d 父目录 = %d\n", temCtx.fileVolumeName.Length,temCtx.fileName.Length));
					//KdPrint(("文件路径:= %wZ , 文件类型 = %wZ", &temCtx.fileFullPath,&temCtx.fileStyle));	
					//KdPrint(("所在卷 =%wZ,父目录=%wZ \n ",&temCtx.fileVolumeName,&temCtx.fileName));	

		
	//		ULONG replyLength;  
	//		SCANNER_REPLY   Reply = {0};  
	//		replyLength = sizeof(SCANNER_REPLY);  

	//		PSCANNER_NOTIFICATION notification =(PSCANNER_NOTIFICATION) ExAllocatePool(NonPagedPool,sizeof(SCANNER_NOTIFICATION)); 
	////		if (notification == NULL)return ;  
	//		RtlZeroMemory(notification, sizeof(SCANNER_NOTIFICATION));  
	//		//notification->bCreate = Create;  
	//		RtlCopyMemory(notification->ProcessName, pName,strlen(pName)+1);

	//		status = FltSendMessage(gFilterHandle,   //句柄
	//			                    &gClientPort, //客户端端口
	//			                    notification,//发送缓冲
	//			                    sizeof(SCANNER_NOTIFICATION), //发送缓冲区的大小
	//								&Reply,
	//								&replyLength,
	//								NULL
	//								);

	//		if (NT_SUCCESS(status))  
	//			{  
	//			  KdPrint(("发送成功  %d\n", replyLength));  
	//			}  
	//		else  
	//			{  
	//				KdPrint(("发送失败  status = %08x\n",status));  
	//			}  



		   /* CHAR pszDest[30];
		    ULONG cbDest = 30;
			LPCSTR pszFormat = "%s %d + %d = %d.";
			CHAR* pszTxt = "The answer is";

			RtlStringCbPrintfA(pszDest, cbDest, pszFormat, pszTxt, 1, 2, "3\n");*/
		//	KdPrint(("%s",pszDest));




			



			//设置事件为有信号，通知  
			//KeSetEvent(g_pEventObject, 0, FALSE);  


			//if (pathListNode == NULL)
			//{
			//	return   FLT_POSTOP_FINISHED_PROCESSING;;
			//}
			//wcscpy(pathListNode->xxPath,L"你好！");
			//KeAcquireSpinLock(&HidePathListLock,&Irql);
			//InsertTailList(&HidePathListHeader,&pathListNode->listNode);
			//KeReleaseSpinLock(&HidePathListLock,Irql);

		} 
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{

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
	__try{

	//获取文件信息
	status = GetFileInformation(Data,FltObjects,&temCtx);
	if (NT_SUCCESS(status))
		{

			PCHAR procName=GetCurrentProcessName(ProcessNameOffset);
			PEPROCESS  p = FltGetRequestorProcess(Data);



			ULONG ProcessId = FltGetRequestorProcessId(Data);  
			ULONG ThreadId = (ULONG)PsGetThreadId(Data->Thread);
			HANDLE ID =  PsGetCurrentProcessId();


			UINT32 Pid = 0 , PPid = 0;
			EnumProcess(ProcessId,&Pid,&PPid);
			


			if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation)
			{
				if (!IsSecretProcess(procName))
				{
					//获取系统运行时间，此函数返回值已被处理只返回开机到到现在的秒数，可以放在日志的开头
					ULONG Time = GetTime();
					CHAR T[100]={0},PID[100]={0},PPID[100] ={0}  ;

					IntegerToChar(Time,T);
					IntegerToChar(PPid,PPID);
					IntegerToChar(Pid,PID);
					//KdPrint(("%s \n",T));
					//KdPrint(("PPID = %s,PID = %s \n",PPID,PID));

					CHAR FileName[260] ={0}; 

					NPUnicodeStringToChar(&temCtx.fileVolumeName, FileName,temCtx.fileVolumeName.Length);
					//KdPrint((" FileName = %s",FileName));
					//T=0;OP=1;C=test.exe;  PID=123;PPID=321;P=\\Device\\HarddiskVolume1\\test;S=15
					//CHAR STR[260] = {"T="};
					CHAR STR[260] = "XXX;";

					/*strcat(STR,T);strcat(STR,";OP=2;C="); strcat(STR,procName);strcat(STR,";PID=");
					strcat(STR,PID);strcat(STR,";PPID="); strcat(STR,PPID);strcat(STR,";P=");
					strcat(STR,FileName);strcat(STR,";S="); strcat(STR,"1555\r\n");*/
					//KdPrint(("%s",STR));

					strcat(STR,T);strcat(STR,";2;"); 
					strcat(STR,procName);strcat(STR,";");
					strcat(STR,PID);strcat(STR,";"); strcat(STR,PPID);strcat(STR,";");
					strcat(STR,FileName);strcat(STR,"\r\n"); 

				

				   PLOG_LIST pathListNode ,pathList;
				   pathListNode = (PLOG_LIST)ExAllocatePool(NonPagedPool,sizeof(LOG_LIST));
				   if (pathListNode == NULL)
				   {
					   KdPrint(("队列初始化失败  \n"));  
				   }
				   RtlCopyMemory(pathListNode->xxPath,STR,strlen(STR));
				   InsertTailList(&HidePathListHeader,&pathListNode->listNode);//插入队尾

				   //设置事件为有信号，通知  
				 //  KeSetEvent(g_pEventObject, 0, FALSE); 

				}
		   }


			if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation)
			{
				PCHAR procName=GetCurrentProcessName(ProcessNameOffset);
				if (!IsSecretProcess(procName))
				{
					//获取系统运行时间，此函数返回值已被处理只返回开机到到现在的秒数，可以放在日志的开头
					ULONG Time = GetTime();
					CHAR T[100]={0},PID[100]={0},PPID[100] ={0}  ;

					IntegerToChar(Time,T);
					IntegerToChar(PPid,PPID);
					IntegerToChar(Pid,PID);

					//KdPrint(("%s \n",T));
					//KdPrint(("PPID = %s,PID = %s \n",PPID,PID));

					CHAR FileName[260] ={0}; 

					NPUnicodeStringToChar(&temCtx.fileVolumeName, FileName,temCtx.fileVolumeName.Length);
					//KdPrint((" FileName = %s",FileName));
					//T=0;OP=1;C=test.exe;  PID=123;PPID=321;P=\\Device\\HarddiskVolume1\\test;S=15
					//CHAR STR[260] = {"T="};
					CHAR STR[260] = "XXX;";

					/*strcat(STR,T);strcat(STR,";OP=3;C="); strcat(STR,procName);strcat(STR,";PID=");
					strcat(STR,PID);strcat(STR,";PPID="); strcat(STR,PPID);strcat(STR,";P=");
					strcat(STR,FileName);strcat(STR,";S="); strcat(STR,"1555\r\n");*/
				//	KdPrint(("%s",STR));
					strcat(STR,T);strcat(STR,";3;"); 
					strcat(STR,procName);strcat(STR,";");
					strcat(STR,PID);strcat(STR,";"); strcat(STR,PPID);strcat(STR,";");
					strcat(STR,FileName);strcat(STR,"\r\n"); 



					PLOG_LIST pathListNode ,pathList;
					pathListNode = (PLOG_LIST)ExAllocatePool(NonPagedPool,sizeof(LOG_LIST));
					if (pathListNode == NULL)
					{
						KdPrint(("队列初始化失败  \n"));  
					}
					RtlCopyMemory(pathListNode->xxPath,STR,strlen(STR));
					InsertTailList(&HidePathListHeader,&pathListNode->listNode);//插入队尾

				}
			}

					/*KdPrint(("文件类型 = %d,文件路径:= %d ", temCtx.fileStyle.Length,temCtx.fileFullPath.Length));
					KdPrint(("所在卷:= %d 父目录 = %d\n", temCtx.fileVolumeName.Length,temCtx.fileName.Length));
					KdPrint(("文件路径:= %wZ , 文件类型 = %wZ", &temCtx.fileFullPath,&temCtx.fileStyle));	
					KdPrint(("所在卷 =%wZ,父目录=%wZ \n ",&temCtx.fileVolumeName,&temCtx.fileName));	*/

				
			
		} 
		}	
		__except(EXCEPTION_EXECUTE_HANDLER)
	    {

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
	
	 PAGED_CODE();

	 UNREFERENCED_PARAMETER( PortCookie );
	 UNREFERENCED_PARAMETER( OutputBufferLength );
	 UNREFERENCED_PARAMETER(InputBuffer);
	 UNREFERENCED_PARAMETER(InputBufferLength);

	  WCHAR *p;
	 __try{
		  
		 p = (PWCHAR)InputBuffer;
		 if (InputBuffer != NULL)
		 {
			 //KdPrint(("用户发来的信息是： %S\n",p));
			 KdPrint(("用户发来的信息是： %S \n",InputBuffer));
			 KdPrint(("InputBufferLength = %d \n",InputBufferLength));
		 }	
	 }
	 __except(EXCEPTION_EXECUTE_HANDLER){
        KdPrint(("%s \n",p));
   }
	return STATUS_SUCCESS;

}



VOID 
	MyMiniFilterLoadImage( __in_opt PUNICODE_STRING FullImageName, __in HANDLE ProcessId, __in PIMAGE_INFO ImageInfo )
{
	UNREFERENCED_PARAMETER(ImageInfo);

	if (FullImageName)
	{
		//DbgPrint("MyMiniFilterLoadImage, image name: %wZ, pid: %d\n", FullImageName, ProcessId);
	}
//	else
		//DbgPrint("MyMiniFilterLoadImage, image name: null, pid: %d\n", ProcessId);
}




VOID
	MyMiniFilterProcessNotify(
	IN HANDLE  ParentId,
	IN HANDLE  ProcessId,
	IN BOOLEAN  Create
	)
{
	//DbgPrint("MyMiniFilterProcessNotify, pid: %d, tid: %d, create: %d\n", ParentId, ProcessId, Create);
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