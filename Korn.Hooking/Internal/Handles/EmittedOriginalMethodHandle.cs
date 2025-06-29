using Korn;
using Korn.Utils;
using System;

unsafe struct EmittedOriginalMethodHandle
{
    public static EmittedOriginalMethodHandle* Emit(byte[] originalPrologue, void* stubEntryPoint)
    {
        var handle = (EmittedOriginalMethodHandle*)Memory.Alloc(originalPrologue.Length + Assembler.JmpRel32Size + sizeof(IntPtr));
        var result = handle;

        ((Assembler*)&handle)
        ->WriteBytes(originalPrologue)
        ->JmpRel32PtrNextInst()
        ->WriteInt64((long)stubEntryPoint);

        return result;
    }
}