
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


//
///************************************************************************/
///*读取文件加密信息 , 是不是已经加密？  2017.9.11 ctx是当前文件的句柄，keyWord是策略表                                                         */
///************************************************************************/
//
//#pragma  LOCKEDCODE
//NTSTATUS GetFileEncryptInfoToCtx(__inout PFLT_CALLBACK_DATA Data,
//								  __in PCFLT_RELATED_OBJECTS FltObjects,
//								  __inout PSTREAM_HANDLE_CONTEXT ctx)
//{
//	NTSTATUS status;
//	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
//
//	//检查中断级
//	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
//	{
//		return STATUS_UNSUCCESSFUL;
//	}
//
//	//判断是否文件夹
//	BOOLEAN isDir;	
//	status=FltIsDirectory(FltObjects->FileObject,FltObjects->Instance,&isDir);
//
//	if (NT_SUCCESS(status))
//	{
//		//文件夹直接跳过
//		if (isDir)
//		{
//			return status;
//		}
//		else
//		{
//			//获取文件名称
//			status=FltGetFileNameInformation(Data,
//				FLT_FILE_NAME_OPENED|FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
//				&nameInfo);
//
//			if (NT_SUCCESS(status))
//			{
//				//获取当前文件路径
//				FltParseFileNameInformation(nameInfo);
//
//				//判断该文件类型是否是加密类型，(策略表,文件名，当前文件的信息)ctx->keyWord文件类型
//				BOOLEAN file_name = IsInKeyWordList( keyWord,
//													 &(nameInfo->Name),
//													 &(ctx->keyprocess));
//				
//				if(file_name)
//				{
//
//					//获取文件信息
//					FILE_STANDARD_INFORMATION fileInfo;
//
//					status = FltQueryInformationFile(FltObjects->Instance,
//													Data->Iopb->TargetFileObject,
//													&fileInfo,
//													sizeof(FILE_STANDARD_INFORMATION),
//													FileStandardInformation,
//													NULL);
//
//				}
//				else
//				{
//					//////////////DbgPrint("no a filt file\n");
//				}
//				
//			}
//			else
//			{
//			//////////////DbgPrint("can not read filename\n");
//			}
//		}
//	}
//	else
//	{
//		//////////////DbgPrint("test dir fail\n");
//	}
//	if (NULL!= nameInfo)
//	{
//		FltReleaseFileNameInformation(nameInfo);
//	}
//	return status;
//}


/************************************************************************/
/*                         策略表操作                                    */
/************************************************************************/
//从字符串中构造一个策略表，返回表头
/*
字符串格式:“.txt=nopad.exe,TxtReader.exe,;.cad=*,;.jpg=ImageView.exe,explore.exe,;”
*/

//PTYPE_KEY_PROCESS GetStrategyFromString(CHAR *StrategyString)
//{
//	//return NULL;
//	int stringLen=strlen(StrategyString);
//	//行标志符
//	CHAR l_end=';';
//
//
//	//行的首偏移
//	int lineStart=0;
//	//行的尾偏移
//	int lineEnd=-1;
//	//行的分割符偏移
//	int lineDiv=0;
//
//	//策略表首部
//	TYPE_KEY_PROCESS keyword_head;
//
//
//	keyword_head.next=NULL;
//
//	//解析策略串
//	for(int i=0;i<stringLen;i++)
//	{
//		//////////////DbgPrint("start to file line end");
//		//查找每个进程的结束标志
//		if(StrategyString[i]==l_end)  
//		{	
//			//行首是上次的行尾加1
//			lineStart=lineEnd+1;
//			lineEnd=i;
//
//			//查找分割符
//			for(lineDiv=lineStart;lineDiv<lineEnd;lineDiv++)
//			{
//				if(StrategyString[lineDiv]!=l_end)continue;
//
//				//读取关键字
//				//分配空间
//				PTYPE_KEY_PROCESS kw=(PTYPE_KEY_PROCESS)ExAllocatePoolWithTag( NonPagedPool,
//					sizeof(TYPE_KEY_PROCESS),
//					BUFFER_SWAP_TAG );
//
//				if (kw!=NULL)
//				{
//
//					//进程连首部
//					PROCESS_INFO proc_head;
//					proc_head.next=NULL;
//
//					//////////////DbgPrint("start to fine proc div");
//
//					int pro_div_end=lineDiv;//进程分割结束
//					int pro_div_start=pro_div_end;//进程分割开始
//					//解析进程名
//
//					for (int j=lineDiv+1;j<lineEnd;j++)
//					{
//						//匹配到进程分割符
//						if(StrategyString[j]!=pro_div)continue;
//
//						pro_div_start=pro_div_end+1;
//						pro_div_end=j;
//						//
//						//读取进程名
//						PPROCESS_INFO pi=(PPROCESS_INFO)ExAllocatePoolWithTag( NonPagedPool,
//							sizeof(PROCESS_INFO),
//							BUFFER_SWAP_TAG );
//
//						if(pi!=NULL)
//						{
//
//							//插入到进程链表
//							pi->next=proc_head.next;
//							proc_head.next=pi;
//							//
//							RtlZeroMemory(pi->processName,PROCESS_NAME_LEN);
//
//
//							//拷贝进程名称
//							size_t proName_size=pro_div_end-pro_div_start;
//							size=proName_size<PROCESS_NAME_LEN?proName_size:PROCESS_NAME_LEN;
//
//							RtlCopyMemory(pi->processName,&(StrategyString[pro_div_start]),size);
//				
//							DbgPrint("*******fine a process %s \n",pi->processName);
//
//							//关联到关键字
//						}
//
//					}
//
//					//进程名解析结束
//					//关联到关键字
//					kw->processInfo=proc_head.next;
//
//				}
//
//			}
//			//解析行结束
//
//		}
//		//查找行结束
//	}
//	//解析结束
//
//	//返回关键字首部
//	return keyword_head.next;
//
//}

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

	//KdPrind(("GetCurrentProcessName进程名 = %s\n",nameptr));
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




/** 获取文件的路径，类型**/

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
	status=FltIsDirectory(FltObjects->FileObject,FltObjects->Instance,&isDir);

	if (NT_SUCCESS(status))
	{
		//文件夹直接跳过
		if (isDir)
		{
			return status;
		}
		else
		{
			//获取文件名称
			status=FltGetFileNameInformation(Data,
				FLT_FILE_NAME_OPENED|FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
				&nameInfo);

			if (NT_SUCCESS(status))
			{
				FltParseFileNameInformation(nameInfo);
			    ctx->fileFullPath = nameInfo->Name;
				ctx->fileStyle = nameInfo->Extension;
				ctx->fileVolumeName = nameInfo->Volume;
				ctx->fileName  = nameInfo->ParentDir;
			}
		}
	}
	if (NULL!= nameInfo)
	{
		FltReleaseFileNameInformation(nameInfo);
	}

	return status;

}




//----------------------------------------------------------------------
//
//	GetCurrentTimeString
//
//	Get current time string. (format: %d-%02d-%02d %02d:%02d:%02d)
//
//	----------------------------------------------------------------------

//PCHAR  GetCurrentTimeString()
//{
//	static CHAR  szTime[128];
//	LARGE_INTEGER SystemTime;
//	LARGE_INTEGER LocalTime;
//	TIME_FIELDS  timeFiled;
//
//	KeQuerySystemTime(&SystemTime);
//	ExSystemTimeToLocalTime(&SystemTime, &LocalTime);
//	RtlTimeToTimeFields(&LocalTime, &timeFiled);
//	sprintf(szTime, "%d-%02d-%02d %02d:%02d:%02d"
//		, timeFiled.Year
//		, timeFiled.Month
//		, timeFiled.Day
//		, timeFiled.Hour
//		, timeFiled.Minute
//		, timeFiled.Second
//		);
//
//	return szTime;
//}


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