using Korn.Utils.Assembler;
using System;
using System.IO;
using System.Reflection;
using static Korn.Hooking.MethodAllocator;

namespace Korn.Hooking
{
    public unsafe class MethodStub
    {
        const int MaxStubCodeSize = 0x1000;

        public MethodStub(MethodInfo methodInfo) 
        {
            this.methodInfo = methodInfo;

            methodStatement = new MethodStatement(methodInfo);
            methodStatement.EnsureMethodIsCompiled();
            methodStatement.EnsureMethodIsAccessible();

            hooksArray = MethodAllocator.Instance.CreateLinkedArray();
            indirect = MethodAllocator.Instance.CreateIndirect(methodStatement.MethodPointer);

            BuildStub();
            DisableRedirection();
            PrepareRedirection();
        }

        MethodInfo methodInfo;
        MethodStatement methodStatement;
        LinkedArray hooksArray;
        Indirect indirect;
        AllocatedRoutine stubRoutine;
        int routineStubOffset;
        IntPtr callOritinalMethod => stubRoutine.Address;
        IntPtr stubMethod => stubRoutine.Address + routineStubOffset;
        byte[] originalPrologueBytes;

        public void EnableRedirection() => *indirect.IndirectAddress = stubMethod;
        public void DisableRedirection() => *indirect.IndirectAddress = callOritinalMethod;
        public LinkedArray.Node* AddHook(IntPtr address) => hooksArray.AddNode(address);
        public void RemoveHook(LinkedArray.Node* node) => hooksArray.RemoveNode(node);

        void BuildStub()
        {
            var methodAddress = methodStatement.MethodPointer;

            stubRoutine = MethodAllocator.Instance.CreateAllocatedRoutine(MaxStubCodeSize);
            Console.WriteLine($"{stubRoutine.Address:X2}");
            BuildRoutineCode();
        }

        static byte[] GetPrologueBytes(IntPtr method)
        {
            const int JmpRel32PointerSize = 6;

            var length = Disassembler.CalculateMinInstructionLength((byte*)method, JmpRel32PointerSize);
            var bytes = Utils.Memory.MemoryExtensions.Read(method, length);
            return bytes;
        }

        void BuildRoutineCode()
        {
            var code = (byte*)stubRoutine.Address;
            originalPrologueBytes = GetPrologueBytes(methodStatement.MethodPointer);
            routineStubOffset = WritePrologueInRoutineCode(&code);
            WriteRoutineCode(&code);

            var codeSize = (int)(code - (byte*)stubRoutine.Address);
            // should be fucked up sooner, but if it's alive — throw exception
            if (codeSize > MaxStubCodeSize)
                throw new KornError(
                    "Korn.Hooking.StubBuilder.BuildStub->CreateRoutineCode: ",
                    $"The routine code was requested more than {nameof(MaxStubCodeSize)} bytes for code"
                );

            stubRoutine.FixSize(codeSize);
        }

        int WritePrologueInRoutineCode(byte** pcode)
        {
            var start = *pcode;

            ((Assembler*)pcode)
            ->WriteBytes(originalPrologueBytes)
            ->MovRax64(methodStatement.MethodPointer + originalPrologueBytes.Length)
            ->JmpRax();

            return (int)((long)*pcode - (long)start);
        }

        // do not forgot to fix 0x20 rsp

        /*
         * 
         * rbx - temp register
         * r10 - hook address
         * r11 - reserved rcx
         * r12 - reserved rdx
         * r13 - reserved r8
         * r14 - reserved r9
         * 
        */
        void WriteRoutineCode(byte** pointer_code)
        {
            var arguments = methodInfo.GetParameters();
            var hasReturnValue = methodInfo.ReturnType != typeof(void);
            var argumentsCount = arguments.Length;
            var paramsCount = argumentsCount + (hasReturnValue ? 1 : 0);

            var epilogueAddress = IntPtr.Zero;

            var maxStack = CalculateMaxStack() + 0x20;

            var entryPoint = (IntPtr)(*pointer_code);
            var asm = (Assembler*)pointer_code;
            var stackPointer = maxStack;

            // prologue
            asm
            ->PushRbx()
            ->SubRsp32(maxStack)
            ->MovR1064(hooksArray.RootNode);

            if (argumentsCount > 0)
                asm->MovRspPtrOff32Rcx(stackPointer -= 8);

            if (argumentsCount > 1)
                asm->MovRspPtrOff32Rdx(stackPointer -= 8);

            if (argumentsCount > 2)
                asm->MovRspPtrOff32R8(stackPointer -= 8);

            if (argumentsCount > 3)
                asm->MovRspPtrOff32R9(stackPointer -= 8);

            stackPointer = maxStack;

            // entry
            var func_getNode = asm->GetCurrentAddress();
            asm->MovRaxR10Ptr();

            // calling hook
            asm
            ->PushR10()
            ->PushR11()
            ->PushR12()
            ->PushR13()
            ->PushR14()
            ->PushR15();

            if (paramsCount > 0)
                asm
                ->MovRcxRsp()
                ->AddRcx32(stackPointer -= 8);

            if (paramsCount > 1)
                asm
                ->MovRdxRsp()
                ->AddRdx32(stackPointer -= 8);

            if (paramsCount > 2)
                asm
                ->MovR8Rsp()
                ->AddR832(stackPointer -= 8);

            if (paramsCount > 3)
                asm
                ->MovR9Rsp()
                ->AddR932(stackPointer -= 8);

            var stackForCall = 0;
            for (var i = 3; i < paramsCount; i++)
            {
                asm
                ->MovRbpRsp()
                ->AddRbp32(paramsCount * 8 - stackForCall)
                ->MovRspPtrOff32Rbp(stackForCall += 8);
                stackPointer -= 8;
            }

            asm
            ->CallRax()
            ->PopR15()
            ->PopR14()
            ->PopR13()
            ->PopR12()
            ->PopR11()
            ->PopR10();

            // checking calling result
            asm
            ->CmpRax8(0)
            ->JeRel32(0xFFFFFFFF);
            var return1Label = asm->GetPreviousIntValueLabel();

            // check next node
            asm
            ->MovR10R10PtrOff8(0x08)
            ->CmpR108(0)
            ->JneRel32(func_getNode);

            // call original method
            stackPointer += arguments.Length * 8;
            if (argumentsCount > 0)
                asm->MovRcxPspPtrOff32(stackPointer -= 8);
            if (argumentsCount > 1)
                asm->MovRdxPspPtrOff32(stackPointer -= 8);
            if (argumentsCount > 2)
                asm->MovR8PspPtrOff32(stackPointer -= 8);
            if (argumentsCount > 3)
                asm->MovR9PspPtrOff32(stackPointer -= 8);

            stackForCall = 0;
            for (var i = 3; i < argumentsCount; i++)
            {
                asm
                ->MovRbpRsp()
                ->AddRbp32((argumentsCount - i) * 8)
                ->MovRspPtrOff32Rbp(stackForCall += 8);
                stackPointer -= 8;
            }

            //var shouldFixStack = maxStack % 16 != 0;
            //asm->SubRsp8(8);
            asm->CallRel32(entryPoint - routineStubOffset);
            //asm->AddRsp8(8);

            // epilogue
            epilogueAddress = asm->GetCurrentAddress();
            asm->WriteInIntLabelOffset(return1Label, epilogueAddress);

            asm->AddRsp32(maxStack);

            asm
            ->PopRbx()
            ->Ret();

            int CalculateMaxStack()
            {
                var registers = 1;
                var returnAddress = 1;
                var addictional = hasReturnValue ? 1 : 0;
                var callStack = 4 + paramsCount > 4 ? ((paramsCount - 4) * 2) : 0;
                return (((registers + returnAddress + addictional + callStack) + 1) / 2 * 2 + 1) * 8;
            }
        }

        void PrepareRedirection()
        {
            var method = methodStatement.MethodPointer;
            var asm = (Assembler*)&method;
            asm->JmpRel32Ptr(indirect.Address);
        }

        class Stack
        {
            public Stack(MethodInfo method)
            {
                HasReturnType = method.ReturnType != typeof(void);
                ArgumentsCount = method.GetParameters().Length;
                ParamsCount = ArgumentsCount + (HasReturnType ? 1 : 0);
                MaxStack = CalculateMaxStack();
            }

            public readonly bool HasReturnType;
            public readonly int ArgumentsCount;
            public readonly int ParamsCount;
            public readonly int MaxStack;

            int CalculateMaxStack()
            {
                return (ParamsCount * 2) + 0x20;
            }
        }
        
        struct StackEntry
        {

            public class Factory
            {
                public Factory(int maxStack)
                {

                }
            }
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