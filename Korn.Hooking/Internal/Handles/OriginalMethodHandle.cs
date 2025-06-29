using Korn;
using Korn.Utils;
using System;

unsafe struct OriginalMethodHandle
{
    public byte[] ExtractPrologueBytes()
    {
        fixed (OriginalMethodHandle* self = &this)
        {
            var length = Disassembler.CalculateMinInstructionLength((byte*)self, Assembler.JmpRel32Size);
            if (length == -1)
                throw new Exception($"OriginalMethodHandle.ExtractPrologueBytes: Passed wrong method asm code. Method pointer: {(IntPtr)self}");

            var bytes = Memory.Read(self, length);
            return bytes;
        }
    }
}