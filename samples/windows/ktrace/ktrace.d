#pragma D option quiet
#pragma D option destructive

struct ustr{uint16_t buffer[256];};

inline ULONG_PTR MmHighestUserAddress = 0x7FFFFFFEFFFF;

syscall::Nt*:entry
{
    if(pid == 4)
    {
        /* printf("%s [Caller %s] 0x%p, 0x%x\n",probefunc, execname, curthread, tid); */
        
        if(probefunc == "NtOpenKey")
        {
            attr = (POBJECT_ATTRIBUTES)arg2;
            if(attr->ObjectName)
            {
                temp = ((PUNICODE_STRING)attr->ObjectName)->Buffer;
                len = ((PUNICODE_STRING)(attr->ObjectName))->Length / 2;
                printf("%Y: Open RegKeyName:%*.*ws\n",walltimestamp, len,len,
                    ((struct ustr*)temp)->buffer);
            }
        }

        if(probefunc == "NtCreateFile") 
        {
            attr = (POBJECT_ATTRIBUTES)arg2;
            if(attr->ObjectName)
            {
                temp = ((PUNICODE_STRING)attr->ObjectName)->Buffer;
                len = ((PUNICODE_STRING)(attr->ObjectName))->Length/2;
                printf("%Y: Create FileName: %*.*ws\n",walltimestamp, len,len,
                    ((struct ustr*)temp)->buffer);
            }
        }

        if(probefunc == "NtQueryValueKey") 
        {
            temp = ((PUNICODE_STRING)arg1)->Buffer;
            len = ((PUNICODE_STRING)arg1)->Length/2;
            printf("%Y: value name: %*.*ws\n",walltimestamp,len,len,
                ((struct ustr*)temp)->buffer);
        }

        if(probefunc == "NtOpenFile")
        {
            attr = (POBJECT_ATTRIBUTES)arg2;
            if(attr->ObjectName)
            {
                temp = ((PUNICODE_STRING)attr->ObjectName)->Buffer;
                len =((PUNICODE_STRING)(attr->ObjectName))->Length / 2;
                printf("%Y,Open File Name: %*.*ws\n",walltimestamp,len,len,
                    ((struct ustr*)temp)->buffer);
            }
        }

        if(probefunc == "NtCreateSection") {
            attr = (POBJECT_ATTRIBUTES)arg2;
            if(attr->ObjectName)
            {
                temp = ((PUNICODE_STRING)attr->ObjectName)->Buffer;
                len = ((PUNICODE_STRING)(attr->ObjectName))->Length / 2;
                printf("%Y, Create Section Name: %*.*ws\n",walltimestamp,len,len,
                    ((struct ustr*)temp)->buffer);
            }
        }

        if(probefunc == "NtCreateThreadEx"){
            this->addr = (uintptr_t)arg4;
            if(this->addr > MmHighestUserAddress)
                printf("%Y: start addr: %p\n",walltimestamp,this->addr);
        }

        if(probefunc == "NtCreateEvent"){
            attr = (POBJECT_ATTRIBUTES)arg2;
            if(attr->ObjectName)
            {
                temp = ((PUNICODE_STRING)attr->ObjectName)->Buffer;
                len = ((PUNICODE_STRING)(attr->ObjectName))->Length / 2;
                printf("%Y: Create Event Name: %*.*ws\n",walltimestamp,len,len,
                    ((struct ustr*)temp)->buffer);
            }
        }

        if(probefunc=="NtCreateSymbolicLinkObject"){
            attr = (POBJECT_ATTRIBUTES)arg2;
            if(attr->ObjectName)
            {
                temp = ((PUNICODE_STRING)attr->ObjectName)->Buffer;
                len = ((PUNICODE_STRING)(attr->ObjectName))->Length / 2;
                printf("%Y: Create SymbolicLinkObject Name: %*.*ws\n",walltimestamp,len,len,
                    ((struct ustr*)temp)->buffer);
            }
        }

        if(probefunc == "NtQuerySystemInformation") {
            printf("%Y: system info class: 0x%x\n",walltimestamp,arg0);
        }
    }
        
}