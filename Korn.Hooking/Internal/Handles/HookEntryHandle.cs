using System.Runtime.InteropServices;

unsafe struct HookEntryHandle
{
    /*nullable*/ public HookEntryHandle* NextEntry;
    /*nullable*/ public void* EntryPoint;
}
