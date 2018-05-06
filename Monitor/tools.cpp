
///////////////////////////////////////////////////////////////////////////////
///

/// 此部分主要是一些函数的声明及实现
///
/// 
///
/// 
///  .
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

#include "tools.h"
#define  ENCRYPTFILE_HEADER_BUFFER_TAG '123'
#define  ENCRYPTFILE_BUFFER_TAG '234'
#define PAGEDCODE code_seg("PAGE")  
#define LOCKEDCODE code_seg()  



/************************************************************************/
/* 查找匹配串 返回匹配的偏移，不匹配返回-1                                  */
/************************************************************************/
INT UnicodeStringIndexOf(UNICODE_STRING *sour,UNICODE_STRING *val)
{
	//原串长度必须大于比较串
	if((sour->Length)<(val->Length))
	{

		return -1;
	}

	int i;
	//每个字符开始
	int sour_len=sour->Length/2;
	int val_len=val->Length/2;
	int len=sour_len-val_len+1;

	//////////////DbgPrint("sour is %wZ and val is %wZ",sour,val);
	//////////////DbgPrint("sour_len is %d and val_len is %d and len is %d",sour_len,val_len,len);
	for(i=0;i<len;i++)
	{
		//标志，表示当前偏移开始是否匹配目标串
		bool flag=true;
		for(int j=0;j<val_len;j++)
		{
			//如果不匹配，则把flag设为false,不需继续比较;
			WCHAR c1=sour->Buffer[i+j];
			WCHAR c2=val->Buffer[j];
			//////////////DbgPrint("C1 IS %C AND C2 IS %C",c1,c2);
			if(c1!=c2)
			{
				flag=false;
				break;
			}
		}
		//flag为true，证明当前偏移匹配成功返回
		if(flag)
		{

			return i;
		}
	}
	return -1;
}



//释放进程链表
void FreeProcessInfoList(PPROCESS_INFO head)
{
	PPROCESS_INFO tmp=NULL;
	PPROCESS_INFO next=NULL;

	tmp=head;
	while(tmp!=NULL)
	{
		next=tmp->next;
		ExFreePoolWithTag(tmp,BUFFER_SWAP_TAG) ;
		tmp=next;
	}
}
//释放一个策略表
void FreeStrategy(PTYPE_KEY_PROCESS head)
{
	PTYPE_KEY_PROCESS tmp=NULL;
	PTYPE_KEY_PROCESS next=NULL;
	tmp=head;
	while(tmp!=NULL)
	{
		next=tmp->next;
		//删除进程链表
		FreeProcessInfoList(tmp->processInfo);
		ExFreePoolWithTag(tmp,BUFFER_SWAP_TAG);
		tmp=next;		
	}

}

//判断进程名是否为该类型的机密进程,keyWork 为类型指针
BOOLEAN IsSecretProcess(PTYPE_KEY_PROCESS keyWord,CHAR *processName)
{
	if (keyWord==NULL||processName==NULL)
	{
		return FALSE;
	}

	PPROCESS_INFO info = keyWord->processInfo;
	
	while(info!=NULL)
	{
		KdPrint(("当前进程processName=%s\n  策略表中的进程 info->processName=%s\n",processName,info->processName));
		/*if(strncmp(processName,info->processName,strlen(processName))==0)
		{
		return TRUE;
		}*/
		info=info->next;
	}
	return FALSE;
}

/************************************************************************/
/*    获取进程名称偏移                                                 */
/************************************************************************/
//////////////////////////////////////////////////////////////////////////
//获取进程名称


ULONG 
GetProcessNameOffset(
    VOID
    )
{
    PEPROCESS       curproc;
    ULONG             i;
 
    curproc = PsGetCurrentProcess();
 
    //
    // Scan for 12KB, hopping the KPEB never grows that big!
    //
    for( i = 0; i < 3*PAGE_SIZE; i++ ) 
	{
     
        if( !strncmp( "System", (PCHAR) curproc + i, strlen("System") )) 
		{

            return i;
        }
    }
    //
    // Name not found - oh, well
    //
    return 0;
}
 

//2017.9.12
PCHAR
GetCurrentProcessName(ULONG ProcessNameOffset)
{
    PEPROCESS       curproc;
    char            *nameptr;
    ULONG           i;
 
    //
    // We only try and get the name if we located the name offset
    //
    if( ProcessNameOffset ) {
    
        //
        // Get a pointer to the current process block
        //
        curproc = PsGetCurrentProcess();
 
        //
        // Dig into it to extract the name. Make sure to leave enough room
        // in the buffer for the appended process ID.
        //
        nameptr   = (PCHAR) curproc + ProcessNameOffset;
		/*
		#if defined(_M_IA64)
        sprintf( szName + strlen(szName), ":%I64d", PsGetCurrentProcessId());
		#else
        sprintf( szName + strlen(szName), ":%d", (ULONG) PsGetCurrentProcessId());
		#endif
		//*/
 
    } else {
		
       nameptr="";
    }
    return nameptr;
}


/************************************************************************/
/*            字符串函数    chat * 与wchar_t* 互转  2017.9.11    */
/************************************************************************/

void wstr2cstr(const wchar_t *pwstr , char *pcstr, size_t len)
{     
	for (size_t i=0;i<len;i++)
	{
		pcstr[i*2]=(char)(pwstr[i]>>8);//高位
		pcstr[i*2+1]=(char)(pwstr[i]);//地位截断
	}
}    

void cstr2wstr( const char *pcstr,wchar_t *pwstr , size_t len)
{     
	for(size_t i=0;i<len;i++)
	{
		pwstr[i]=(WCHAR)pcstr[i];
	}
}  




/** 获取文件的路径，类型，过滤文件夹（去掉）**/

NTSTATUS GetFileInformation(__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__inout PSTREAM_HANDLE_CONTEXT ctx)
{
	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
	//检查中断级
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	//判断是否文件夹
	BOOLEAN isDir;	
	status = FltIsDirectory(FltObjects->FileObject,FltObjects->Instance,&isDir);


	if (NT_SUCCESS(status))
	{
		//文件夹直接跳过
		if (isDir)
		{
			return STATUS_UNSUCCESSFUL;  //是文件夹直接返回失败
		}
		else
		{
			//获取文件名称FLT_FILE_NAME_OPENED 文件被打开才行
			status=FltGetFileNameInformation(Data,
				FLT_FILE_NAME_NORMALIZED|FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
				&nameInfo);

			if (NT_SUCCESS(status))
			{
					 
				status = FltParseFileNameInformation(nameInfo);
				
				if (NT_SUCCESS(status))
				{
					int i = 1;
					int count = 1;
			
					PWCHAR  p = nameInfo->ParentDir.Buffer;
					/**截取父目录中的第一级目录  2018_5_6*/
					while (p[i] != '\\')
					{
						//KdPrint(("count = %d ,p[i] = %c\n",count,p[i]));
						count++;
						i++;
					}

					ctx->fileFullPath = nameInfo->Name;
					ctx->fileStyle = nameInfo->Extension;
					ctx->fileVolumeName = nameInfo->Volume;
					ctx->ParentDir  = nameInfo->ParentDir;
						/**截取父目录中的第一级目录与卷目录合并  2018_5_6*/
					ctx->fileVolumeName.Length =  ctx->fileVolumeName.Length +2*count;
					ctx->fileVolumeName.MaximumLength =  ctx->fileVolumeName.MaximumLength +2*count;
					//KdPrint(("V = %wZ,length = %d,mAxL = %d ,count = %d\n",&nameInfo->Volume,nameInfo->Volume.Length,nameInfo->Volume.MaximumLength,count));
				   // KdPrint(("Volume = %wZ,length = %d,mAxL = %d \n",&ctx->fileVolumeName,ctx->fileVolumeName.Length,ctx->fileVolumeName.MaximumLength));
				
				}    
			}
		}

		if (NULL!= nameInfo)
		{
			FltReleaseFileNameInformation(nameInfo);
		}
	}
	

	return status;

}




 ULONG	GetTime()
{
	LARGE_INTEGER TickCount = {0};
	LARGE_INTEGER GelinTime = {0};
	LARGE_INTEGER LocalTime = {0};
	TIME_FIELDS NowFields;
	ULONG Inc = 0;
	ULONG Day = 0;
	ULONG Hour = 0;
	ULONG Minute = 0;
	ULONG Second = 0;

	Inc = KeQueryTimeIncrement();
	KeQueryTickCount(&TickCount);
	TickCount.QuadPart *= Inc;
	TickCount.QuadPart /= 10000;
	Day = TickCount.QuadPart / (1000*60*60*24);
	Hour = TickCount.QuadPart % (1000*60*60*24) / (1000*60*60);
	Minute = TickCount.QuadPart % (1000*60*60*24) % (1000*60*60) / (1000*60);
	Second = TickCount.QuadPart % (1000*60*60*24) % (1000*60*60) % (1000*60) / 1000;

	//KdPrint(("系统启动了%2d天%2d小时%2d分钟%2d秒\n", Day, Hour, Minute, Second));

	//ULONG Time[1] = {0};
//	Time[0] = Hour*3600+Minute*60+Second;
	//KdPrint(("系统启动 %2ld秒\n", Time[0]));
	return  (Hour*3600+Minute*60+Second);

	/*KeQuerySystemTime(&GelinTime);
	ExSystemTimeToLocalTime(&GelinTime, &LocalTime);
	RtlTimeToTimeFields(&LocalTime, &NowFields);
	KdPrint(("系统当前时间 : %4d年%2d月%2d日 %2d:%2d:%2d\n",
		NowFields.Year, 
		NowFields.Month,
		NowFields.Day,
		NowFields.Hour,
		NowFields.Minute,
		NowFields.Second));*/
}
  /***判断是否是要过滤掉的进程名  icedxu_2018_5_4**/
 BOOLEAN  IsSecretProcess(CHAR  *processName)
 {
	 PCHAR name = ";System;svchost.exe;vmtoolsd.exe;explorer.exe;SearchProtocol;iexplore.exe;SearchIndexer;taskhost.exe;WmiApSrv.exe;";
	// PCHAR name = "qwef;";
	if (strstr(name,processName) > 0)
	{
		return TRUE;
	}
	return FALSE;
 }





 //根据进程 ID 返回进程 EPROCESS，失败返回 NULL
	 PEPROCESS LookupProcess(HANDLE Pid)
 {
	 PEPROCESS eprocess = NULL;
	 if (NT_SUCCESS(PsLookupProcessByProcessId(Pid, &eprocess))) 
		 return eprocess;
	 else
		 return NULL;
 }
 //枚举进程
	 VOID EnumProcess(ULONG processID)
 {
	 ULONG i = 0;
	 PEPROCESS eproc = NULL;
	 for (i = 4; i<262144; i = i + 4)
	 {
		 eproc = LookupProcess((HANDLE)i);
		 if (eproc != NULL)
		 {
			if (processID == (UINT32)PsGetProcessId(eproc))
			{
				if ( !IsSecretProcess((PCHAR)PsGetProcessImageFileName(eproc)) )
				{
				    	DbgPrint("EPROCESS = %p, PID = %ld, PPID = %ld, Name = %s\n", 
						eproc,
						(UINT32)PsGetProcessId(eproc),
						(UINT32)PsGetProcessInheritedFromUniqueProcessId(eproc),
						PsGetProcessImageFileName(eproc));
					    ObDereferenceObject(eproc);
				}
			}			
		 }
	 }
 }


 //typedef NTSTATUS (*QUERY_INFO_PROCESS) (
	// __in HANDLE ProcessHandle,
	// __in PROCESSINFOCLASS ProcessInformationClass,
	// __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	// __in ULONG ProcessInformationLength,
	// __out_opt PULONG ReturnLength
	// );

 //QUERY_INFO_PROCESS ZwQueryInformationProcess;

 //NTSTATUS PsGetProcessImageFileName(PUNICODE_STRING ProcessImageName)
 //{
	// NTSTATUS status;
	// ULONG returnedLength;
	// ULONG bufferLength;
	// PVOID buffer;
	// PUNICODE_STRING imageName;

	// PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process

	// if (NULL == ZwQueryInformationProcess) {

	//	 UNICODE_STRING routineName;

	//	 RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");

	//	 ZwQueryInformationProcess = 
	//		 (QUERY_INFO_PROCESS) MmGetSystemRoutineAddress(&routineName);

	//	 if (NULL == ZwQueryInformationProcess) {
	//		 DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
	//	 }
	// }
	// 
	//  Step one - get the size we need
	// 
	// status = ZwQueryInformationProcess( NtCurrentProcess(), 
	//	 ProcessImageFileName,
	//	 NULL, // buffer
	//	 0, // buffer size
	//	 &returnedLength);

	// if (STATUS_INFO_LENGTH_MISMATCH != status) {

	//	 return status;

	// }

	// 
	//  Is the passed-in buffer going to be big enough for us?  
	//  This function returns a single contguous buffer model...
	// 
	// bufferLength = returnedLength - sizeof(UNICODE_STRING);

	// if (ProcessImageName->MaximumLength < bufferLength) {

	//	 ProcessImageName->Length = (USHORT) bufferLength;

	//	 return STATUS_BUFFER_OVERFLOW;

	// }

	// 
	//  If we get here, the buffer IS going to be big enough for us, so 
	//  let's allocate some storage.
	// 
	// buffer = ExAllocatePoolWithTag(PagedPool, returnedLength, 'ipgD');

	// if (NULL == buffer) {

	//	 return STATUS_INSUFFICIENT_RESOURCES;

	// }

	// 
	//  Now lets go get the data
	// 
	// status = ZwQueryInformationProcess( NtCurrentProcess(), 
	//	 ProcessImageFileName,
	//	 buffer,
	//	 returnedLength,
	//	 &returnedLength);

	// if (NT_SUCCESS(status)) {
	//	 
	//	  Ah, we got what we needed
	//	 
	//	 imageName = (PUNICODE_STRING) buffer;

	//	 RtlCopyUnicodeString(ProcessImageName, imageName);

	// }

	// 
	//  free our buffer
	// 
	// ExFreePool(buffer);

	// 
	//  And tell the caller what happened.
	//     
	// return status;

 //}





















 //
 // Enable log event: for synchronization
 //
 static KEVENT   gs_eventEnableKeLog;

 //----------------------------------------------------------------------
 //
 // initialization interface
 //
 //----------------------------------------------------------------------
 //
 // initialize the global data structures, when the driver is loading. 
 // (Call in DriverEntry())
 //
 NTSTATUS
	 Dbg_LoadInit()
 {
	 // Initialize the event
	 KeInitializeEvent(&gs_eventEnableKeLog, SynchronizationEvent, TRUE);
	 return STATUS_SUCCESS;
 }

 static void WaitForWriteMutex()
 {
	 // Wait for enable log event
	 KeWaitForSingleObject(&gs_eventEnableKeLog, Executive, KernelMode, TRUE, 0);
	 KeClearEvent(&gs_eventEnableKeLog);
 }
 static void ReleaseWriteMutex()
 {
	 // Set enable log event
	 KeSetEvent(&gs_eventEnableKeLog, 0, FALSE);
 }
 //----------------------------------------------------------------------
 //
 // DbgKeLog
 //
 // Trace to file.
 //
 //----------------------------------------------------------------------
 VOID DbgKeLog(PCHAR lpszLog)
 {
	 if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	 {
		// TOKdPrint(("TKeHook: KeLog: IRQL too hight.../n"));
		 KdPrint(("TKeHook: KeLog: IRQL too hight.../n"));
		 return ;
	 }
	 WaitForWriteMutex();

	 KdPrint(("%s", lpszLog));

	 __try
	 {
		 IO_STATUS_BLOCK  IoStatus;
		 OBJECT_ATTRIBUTES objectAttributes;
		 NTSTATUS status;
		 HANDLE FileHandle = NULL;
		 UNICODE_STRING fileName;
		 RtlInitUnicodeString(&fileName,L"//??//C://KeLog.log") ;
	

		 InitializeObjectAttributes (&objectAttributes,
			 (PUNICODE_STRING)&fileName,
			 OBJ_CASE_INSENSITIVE,  //对大小写敏感
			 NULL,
			 NULL );

		 status = ZwCreateFile(&FileHandle,
			 FILE_APPEND_DATA, //往后加数据
			 &objectAttributes,
			 &IoStatus,
			 0, 
			 FILE_ATTRIBUTE_NORMAL,
			 FILE_SHARE_WRITE,
			 FILE_OPEN_IF, //即使存在也创建
			 FILE_SYNCHRONOUS_IO_NONALERT,
			 NULL,     
			 0 );



			 ZwWriteFile(FileHandle,
				 NULL,
				 NULL,
				 NULL,
				 &IoStatus,
				 lpszLog,
				 strlen(lpszLog),
				 NULL,
				 NULL 
				 );

			 ZwClose(FileHandle);
		


		 ReleaseWriteMutex();
		 return ;
	 }
	 __except(EXCEPTION_EXECUTE_HANDLER)
	 {
		 ReleaseWriteMutex();
		 KdPrint(("TKeHook: DbgKeLog() except: %0xd !!/n", GetExceptionCode()));
		 return ;
	 }
 }