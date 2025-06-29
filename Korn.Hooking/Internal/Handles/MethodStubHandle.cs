using Korn.Utils;
using System;

unsafe struct MethodStubHandle
{
    public EmittedOriginalMethodHandle* EmittedOriginalMethod;
    /*nullable*/
    public HookEntryHandle* FirstEntry;

    public HookEntryHandle* AppendEntry(void* entryPoint)
    {
        fixed (MethodStubHandle* self = &this)
        {
            var pentry = &self->FirstEntry;
            while (*pentry != null)
                pentry = &(*pentry)->NextEntry;

            var entry = *pentry = Memory.Alloc<HookEntryHandle>();
            entry->EntryPoint = entryPoint;
            entry->NextEntry = null;
            return entry;
        }
    }
}