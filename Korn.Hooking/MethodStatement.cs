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

        public void CheckStatement()
        {
            IntPtr method = MethodHandle.GetFunctionPointer();

#if NET8_0
            if (*(uint*)method == 0x66666666)
                method += sizeof(int);

            if (*(ushort*)method == 0x25FF &&
                (*(uint*)(method + 0x06) & 0xFFFFFF) == 0x158B4C &&
                *(ushort*)(method + 0x0D) == 0x25FF)
            {
                var innerMethod = *(nint*)(method + 6 + *(int*)(method + 2));
                if (innerMethod - method == 0x06)
                {
                    (MethodPointer, MethodType) = (method, MethodType.NotCompiledStub);
                    return;
                }

                method = innerMethod;
                if ((*(uint*)method & 0xFFFFFF) == 0x058B48 &&
                    *(byte*)(method + 0x07) == 0x66 &&
                    *(ushort*)(method + 0x0A) == 0x0674)
                {
                    (MethodPointer, MethodType) = (method, MethodType.ThresholdCounterStub);
                    return;
                }



                (MethodPointer, MethodType) = (method, MethodType.DirectNativeStub);
                return;
            }

            // push rbp
            if (*(byte*)method == 0x55)
            {
                (MethodPointer, MethodType) = (method, MethodType.Native);
                return;
            }

            (MethodPointer, MethodType) = (method, MethodType.UnknownStub);
            return;
#elif NET472
            // call rel32
            if (*(byte*)method == 0xE8)
            {
                (MethodPointer, MethodType) = (method, MethodType.NotCompiledStub);
                return;
            }

            // jmp rel32
            if (*(byte*)method == 0xE9)
                method = method + 5 + *(int*)(method + 1);

            // push rbp
            if (*(byte*)method == 0x55)
            {
                (MethodPointer, MethodType) = (method, MethodType.Native);
                return;
            }

            (MethodPointer, MethodType) = (method, MethodType.UnknownStub);
            return;
#endif
        }
    }
}