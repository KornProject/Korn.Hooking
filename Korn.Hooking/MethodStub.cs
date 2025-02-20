using Korn.Utils.Assembler;
using System;
using System.Collections.Generic;
using System.Reflection;
using static Korn.Hooking.MethodAllocator;

namespace Korn.Hooking
{
    public unsafe class MethodStub
    {
        const int MaxStubSize = 0x1000;

        public MethodStub(MethodInfo methodInfo) 
        {
            this.methodInfo = methodInfo;

            methodStatement = new MethodStatement(methodInfo);
            methodStatement.EnsureMethodIsCompiled();

            hooksArray = MethodAllocator.Instance.CreateLinkedArray();
            indirect = MethodAllocator.Instance.CreateIndirect(methodStatement.MethodPointer);

            BuildStub();
        }

        MethodInfo methodInfo;
        MethodStatement methodStatement;
        LinkedArray hooksArray;
        Indirect indirect;
        Routine stubRoutine;
        IntPtr callOritinalMethod;
        IntPtr stubMethod;

        void BuildStub()
        {
            var methodAddress = methodStatement.MethodPointer;

            var routineCode = CreateRoutineCode();
            var routine = MethodAllocator.Instance.CreateRoutine(routineCode);
            this.stubRoutine = routine;

            var code = CreateRoutineCode();
        }

        static byte[] GetPrologueBytes(IntPtr method)
        {
            const int JmpRel32PointerSize = 6;

            var length = Disassembler.CalculateMinInstructionLength((byte*)method, JmpRel32PointerSize);
            var bytes = Utils.Memory.MemoryExtensions.Read(method, length);
            return bytes;
        }

        byte[] CreateRoutineCode()
        {
            var codeBytes = new byte[MaxStubSize];
            fixed (byte* codePointer = codeBytes)
            {
                var code = codePointer;

                var prologueBytes = GetPrologueBytes(methodStatement.MethodPointer);
                var prologueLength = WritePrologueInStub(&code, prologueBytes);
                WriteRoutineCode(&code);

                var codeSize = (int)(code - codePointer);
                // should be fucked up sooner, but if it's alive — throw exception
                if (codeSize > MaxStubSize)
                    throw new KornError(
                        "Korn.Hooking.StubBuilder.BuildStub->CreateRoutineCode: ",
                        $"The routine code was requested more than {nameof(MaxStubSize)} bytes for code"
                    );

                Array.Resize(ref codeBytes, codeSize);
                return codeBytes;
            }
        }

        int WritePrologueInStub(byte** pcode, byte[] prologueBytes)
        {
            var start = *pcode;

            ((Assembler)pcode)
            .WriteBytes(prologueBytes)
            .MovRax64(methodStatement.MethodPointer + prologueBytes.Length)
            .JmpRax();

            return (int)((long)*pcode - (long)start);
        }

        void WriteRoutineCode(byte** code)
        {
            var asm = (Assembler)code;


        }
    }
}

/*
 

        public struct Nada
        {
            public IntPtr Value;
            public Nada* Next;
        }

        static Nada* nodes;

        string A(int a, string b)
        {
            return null;
        }

        static bool B(ref object self, ref int a, ref string b, ref string result)
        {
            Console.WriteLine("" + self + a + b + result);
            return false;
        }

        static string C(object self, int a, string b)
        {
            var node = nodes;
            string result = null;

            do
            {
                var address = node->Value;
                var value = ((delegate* unmanaged<ref object, ref int, ref string, ref string, bool>)address)(ref self, ref a, ref b, ref result);
                if (!value)
                    return result;

                node = node->Next;
            }
            while (node->Next != null);

            return ((MethodStub)self).A(a, b);
        }
*/