#pragma D option quiet
#pragma D option destructive
 
syscall::Nt*:entry
{
    if(pid == 4)
        printf("%s [Caller %s] 0x%p, 0x%x\n",probefunc, execname, curthread, tid);
}