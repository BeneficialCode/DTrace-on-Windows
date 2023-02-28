/*++

Module Name:

    antidebugbyexecname.d

Abstract:

    This script provides antidebug trace ability for a given execname. The execname is case sensitive.

Requirements:

    This script needs symbol's to be configured.

Usage:

     dtrace -s antidebugbyexecname.d <execname>

--*/
#pragma D option quiet
#pragma D option destructive



syscall::Nt*:entry 
/ execname == $1 /
{
    /*printf("%s [Caller %s]\n",probefunc, execname);*/
    if(probefunc == "NtQuerySystemInformation") {
        if(arg0 == 35){
            printf("Detect Kernel Debugger\n");
        }
    }
    
    if(probefunc == "NtQueryInformationProcess") {
        if(arg1 == 0x7){
            printf("Detect ProcessDebutPort\n");
        }

        if(arg1 == 0x1E){
            printf("Detect ProcessDebugObjectHandle\n");
        }

        if(arg1 == 0x1F){
            printf("Detect DebugFlags");
        }
    }

    if(probefunc == "NtSetInformationThread"){
        if(arg1 == 0x11){
            printf("HideFromDebugger\n");
        }
    }

    if(probefunc == "NtQueryInformationProcess"){
        if(arg1 == 0){
            printf("Query Process Basic Information \n");
        }
    }

    if(probefunc == "NtQueryObject"){
        if(arg1 == 2) {
            printf("Query Object Type Information\n");
        }

        if(arg1 == 3) {
            printf("Query Object Types Information\n");
        }
    }

    if(probefunc == "NtClose") {
        printf("Close Handle : 0x%x\n",arg0);
    }

    if(probefunc == "NtSetInformationObject") {
        if(arg1 == 4){
            printf("Set Handle Flag\n");
        }
    }

    if(probefunc == "NtGetContextThread"){
        printf("Get thread by thread handle : 0x%x",arg0);
    }

    if(probefunc == "NtYieldExecution") {
        printf("NtYieldExecution\n");
    }

    if(probefunc == "DbgSetDebugFilterState") {
        printf("DbgSetDebugFilterState\n");
    }
}