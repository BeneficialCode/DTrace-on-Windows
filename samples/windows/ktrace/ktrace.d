#pragma D option quiet
#pragma D option destructive

struct ustr{uint16_t buffer[256];};

inline uintptr_t MmHighestUserAddress = 0x7FFFFFFEFFFF;

int found;
PETHREAD ethread_ptr;

BEGIN
{
    found = 0;
    ethread_ptr=0;
}

syscall::Nt*:entry
{
    if (pid == 4) {
        if (probefunc == "NtOpenKey")
        {
            if(!found) 
            {
                ethread_ptr = curthread;
                found = 1;
            }
        }

        if (ethread_ptr == curthread) {
            if(probefunc != "NtQueryDirectoryFile")
                printf("%s [Caller %s] 0x%p, 0x%x\n", probefunc, execname, curthread, tid);

            if (probefunc == "NtOpenKey")
            {
                attr = (POBJECT_ATTRIBUTES)arg2;
                if (attr->ObjectName)
                {
                    temp = ((PUNICODE_STRING)attr->ObjectName)->Buffer;
                    len = ((PUNICODE_STRING)(attr->ObjectName))->Length / 2;
                    printf("%Y: 0x%p Open RegKeyName:%*.*ws\n", walltimestamp, curthread, len, len,
                        ((struct ustr*)temp)->buffer);
                }
            }

            if (probefunc == "NtCreateFile")
            {
                attr = (POBJECT_ATTRIBUTES)arg2;
                if (attr->ObjectName)
                {
                    temp = ((PUNICODE_STRING)attr->ObjectName)->Buffer;
                    len = ((PUNICODE_STRING)(attr->ObjectName))->Length / 2;
                    printf("%Y: 0x%p Create FileName: %*.*ws\n", walltimestamp, curthread, len, len,
                        ((struct ustr*)temp)->buffer);
                }
            }

            if (probefunc == "NtQueryValueKey")
            {
                temp = ((PUNICODE_STRING)arg1)->Buffer;
                len = ((PUNICODE_STRING)arg1)->Length / 2;
                printf("%Y: 0x%p value name: %*.*ws\n", walltimestamp, curthread, len, len,
                    ((struct ustr*)temp)->buffer);
            }

            if (probefunc == "NtOpenFile")
            {
                attr = (POBJECT_ATTRIBUTES)arg2;
                if (attr->ObjectName)
                {
                    /*temp = ((PUNICODE_STRING)attr->ObjectName)->Buffer;
                    len =((PUNICODE_STRING)(attr->ObjectName))->Length / 2;
                    printf("%Y: 0x%p Open File Name: %*.*ws\n",walltimestamp,curthread,len,len,
                        ((struct ustr*)temp)->buffer);*/
                }
            }

            if (probefunc == "NtCreateSection") {
                attr = (POBJECT_ATTRIBUTES)arg2;
                if (attr->ObjectName)
                {
                    temp = ((PUNICODE_STRING)attr->ObjectName)->Buffer;
                    len = ((PUNICODE_STRING)(attr->ObjectName))->Length / 2;
                    printf("%Y: 0x%p Create Section Name: %*.*ws\n", walltimestamp, curthread, len, len,
                        ((struct ustr*)temp)->buffer);
                }
            }

            if (probefunc == "NtCreateThreadEx") {
                this->addr = (uintptr_t)arg4;
                printf("%Y: 0x%p start addr: %p\n", walltimestamp, curthread, this->addr);
            }

            if (probefunc == "NtCreateEvent") {
                attr = (POBJECT_ATTRIBUTES)arg2;
                if (attr->ObjectName)
                {
                    temp = ((PUNICODE_STRING)attr->ObjectName)->Buffer;
                    len = ((PUNICODE_STRING)(attr->ObjectName))->Length / 2;
                    printf("%Y: 0x%p Create Event Name: %*.*ws\n", walltimestamp, curthread, len, len,
                        ((struct ustr*)temp)->buffer);
                }
            }

            if (probefunc == "NtCreateSymbolicLinkObject") {
                attr = (POBJECT_ATTRIBUTES)arg2;
                if (attr->ObjectName)
                {
                    temp = ((PUNICODE_STRING)attr->ObjectName)->Buffer;
                    len = ((PUNICODE_STRING)(attr->ObjectName))->Length / 2;
                    printf("%Y: 0x%p Create SymbolicLinkObject Name: %*.*ws\n", walltimestamp, curthread, len, len,
                        ((struct ustr*)temp)->buffer);
                }
            }

            if (probefunc == "NtQuerySystemInformation") {
                printf("%Y: 0x%p system info class: 0x%x\n", walltimestamp, curthread, arg0);
            }
        }
    }
        
}

fbt:nt:IoCreateDeviceSecure:entry
{
    temp = ((PUNICODE_STRING)arg2)->Buffer;
    printf("Created device %.*ws \n", ((PUNICODE_STRING)arg2)->Length / 2, ((struct ustr*)temp)->buffer);
}

fbt:nt:IoCreateDevice:entry
{
    temp = ((PUNICODE_STRING)arg2)->Buffer;
    printf("Created device %.*ws \n", ((PUNICODE_STRING)arg2)->Length / 2, ((struct ustr*)temp)->buffer);
}