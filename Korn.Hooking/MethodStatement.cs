using Korn.Utils.Assembler;
using Korn.Utils.Memory;
using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading;

namespace Korn.Hooking
{
    public unsafe class MethodStatement
    {
        public MethodStatement(MethodInfo methodInfo)
        {
            MethodInfo = methodInfo;
            MethodHandle = methodInfo.MethodHandle;
        }

        public MethodInfo MethodInfo;
        public RuntimeMethodHandle MethodHandle;
        public MethodType MethodType;
        public IntPtr MethodPointer;

        public void EnsureMethodIsCompiled()
        {
            if (MethodType.IsNative())
                return;

            RuntimeHelpers.PrepareMethod(MethodHandle);
            while (!MethodType.IsNative())
            {
                Thread.Sleep(1);
                CheckStatement();
            }
        }

        public void EnsureMethodIsAccessible()
        {
            if (MethodPointer == IntPtr.Zero)
                return;

            var mbi = MemoryAllocator.Query(MethodPointer);
            if (!mbi.Protect.IsWritable())
                mbi.SetProtection(MemoryProtect.ExecuteReadWrite);
        }

        public void CheckStatement()
        {
            var method = MethodHandle.GetFunctionPointer();
            var asmPointer = method;
            var asm = (Disassembler*)&asmPointer;

#if NET8_0
            if (asm->IsLengthChangingInstruction)
                asm->SkipLengthChangingInstruction();

            if (asm->IsJmpPtrRel32Instruction &&
                asm->GetNextInstruction()->IsMov10PtrInstruction &&
                asm->GetNextInstruction()->IsJmpPtrRel32Instruction)
            {
                asmPointer = method;
                var innerMethod = asm->GetJmpRel32Operand();
                if (innerMethod - method == 0x06)
                {
                    (MethodPointer, MethodType) = (method, MethodType.NotCompiledStub);
                    return;
                }
                method = innerMethod;

                if (asm->GetNextInstruction()->IsMovRaxPtrInstruction &&
                    asm->GetNextInstruction()->IsDecPtrRaxInstruction &&
                    asm->GetNextInstruction()->IsJeRel8Instruction && asm->GetJmpRel32Operand() == 0x06)
                {
                    (MethodPointer, MethodType) = (innerMethod, MethodType.ThresholdCounterStub);
                    return;
                }

                (MethodPointer, MethodType) = (innerMethod, MethodType.DirectNativeStub);
                return;
            }

            (MethodPointer, MethodType) = (method, MethodType.Native);
#elif NET472
            if (asm->IsCallRel32Instruction)
            {
                (MethodPointer, MethodType) = (method, MethodType.NotCompiledStub);
                return;
            }

            if (asm->IsJmpRel32Instruction)
                method = asm->GetJmpRel32Operand();

            (MethodPointer, MethodType) = (method, MethodType.Native);
#endif
        }
    }
}