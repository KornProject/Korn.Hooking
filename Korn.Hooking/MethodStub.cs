using static Korn.Hooking.MethodAllocator;
using System.Reflection;
using System;
using Korn.Modules.Algorithms;
using Korn.Logger;

namespace Korn.Hooking
{
    public unsafe class MethodStub
    {
        const int MaxStubCodeSize = 0x1000;

        public MethodStub(MethodInfo methodInfo) 
        {
            this.methodInfo = methodInfo;

            methodStatement = MethodStatement.From(methodInfo);

            hooksArray = new LinkedArray();
            indirect = MethodAllocator.Instance.CreateIndirect(methodStatement.NativeCodePointer);

            BuildStub();
            DisableRedirection();
            PrepareRedirection();
        }

        public Routine DEBUG_StubRoutine => stubRoutine;
        public MethodStatement DEBUG_MethodStatement => methodStatement;

        MethodInfo methodInfo;
        MethodStatement methodStatement;
        LinkedArray hooksArray;
        Indirect indirect;
        Routine stubRoutine;
        int routineStubOffset;
        IntPtr callOritinalMethod => stubRoutine.Address;
        IntPtr stubMethod => stubRoutine.Address + routineStubOffset;
        byte[] originalPrologueBytes;

        public void EnableRedirection() => *indirect.IndirectAddress = stubMethod;
        public void DisableRedirection() => *indirect.IndirectAddress = callOritinalMethod;
        public LinkedNode* AddHook(IntPtr address) => hooksArray.AddNode()->SetValue(address);
        public void RemoveHook(LinkedNode* node) => hooksArray.RemoveNode(node);

        void BuildStub()
        {
            stubRoutine = MethodAllocator.Instance.CreateAllocatedRoutine(MaxStubCodeSize);
            BuildRoutineCode();
        }

        static byte[] GetPrologueBytes(IntPtr method)
        {
            var length = Disassembler.CalculateMinInstructionLength((byte*)method, Assembler.JmpRel32Size);
            if (length == -1)
                throw new Exception($"MethodStub.GetPlogueBytes: Passed wrong method asm code. Method pointer: {method}");

            var bytes = Utils.Memory.Read((void*)method, length);
            return bytes;
        }

        void BuildRoutineCode()
        {
            var code = (byte*)stubRoutine.Address;
            originalPrologueBytes = GetPrologueBytes(methodStatement.NativeCodePointer);
            routineStubOffset = WritePrologueInRoutineCode(&code);
            WriteRoutineCode(&code);

            var codeSize = (int)(code - (byte*)stubRoutine.Address);
            // should be fucked up sooner, but if it's alive — throw exception
            if (codeSize > MaxStubCodeSize)
                throw new KornError(
                    "Korn.Hooking.StubBuilder.BuildStub->CreateRoutineCode: ",
                    $"The routine code was requested more than {nameof(MaxStubCodeSize)} bytes for code"
                );

            stubRoutine.Size = codeSize;
        }

        int WritePrologueInRoutineCode(byte** pcode)
        {
            var start = *pcode;

            var asm = (Assembler*)pcode;

            asm->WriteBytes(originalPrologueBytes);

            var address = methodStatement.NativeCodePointer + originalPrologueBytes.Length;
            var addressAdress = (IntPtr)(*pcode + 6);
            asm->JmpRel32Ptr(addressAdress);
            asm->WriteInt64(address);

            return (int)((long)*pcode - (long)start);
        }

        // do not forgot to fix 0x20 rsp
        // in the future handle ref ref arg's, now just use ref type* arg

        /*
         * 
         * r11 - temp register
         * rdi - hook address
         * r10:general - temp storing hook calling result
         * 
        */
        void WriteRoutineCode(byte** pointer_code)
        {
            var stack = new Stack(methodInfo);
            stack.SetInitialPrevStackStartOffset(0x10 /* push: rbp rdi */);
            var methodStack = stack.BuildMethodStack();

            var epilogueAddress = IntPtr.Zero;

            var entryPoint = *(IntPtr*)pointer_code;
            var asm = (Assembler*)pointer_code;

            // prologue
            asm
            ->PushRbp()
            ->PushRdi()
            ->SubRsp32(stack.MaxStack)
            ->MovRdi64(hooksArray.MovelessNodePointer)
            ->MovRdiRdiPtr();

            foreach (var argument in methodStack.Arguments)
            {
                AssemblerExtensions.Move(asm, argument.InputValue, argument.StoreValue);
                AssemblerExtensions.MovePointer(asm, argument.StoreValue, argument.PointerToStoreValue);
            }

            if (methodStack.HasReturnType)
            {
                var returnType = methodStack.ReturnType;
                var stackValue = returnType.StoreValue as StackValue;
                var offset = stackValue.Offset;

                asm
                ->XorR11R11()
                ->MovRspPtrOff32R11(offset);

                AssemblerExtensions.MovePointer(asm, returnType.StoreValue, returnType.PointerToStoreValue);
            }

            // entry
            var func_getNode = asm->GetCurrentAddress();
            asm->MovRaxRdiPtr();

            foreach (var argument in methodStack.Parameters)
                AssemblerExtensions.Move(asm, argument.PointerToStoreValue, argument.CallingValue);

            asm->CallRax();

            // checking calling result
            if (methodStack.HasReturnType)
            {
                asm->MovR10Rax();
                AssemblerExtensions.MoveRax(asm, methodStack.ReturnType.StoreValue);
                asm->CmpR108(0);
            }
            else asm->CmpRax8(0);

            asm->JeRel32(0xFFFFFFFF);
            var return1Label = asm->GetPreviousIntValueLabel();

            // check next node
            asm
            ->MovRdiRdiPtrOff8(0x08)
            ->CmpRdi8(0)
            ->JneRel32(func_getNode);

            // call original method
            foreach (var argument in methodStack.Arguments)
                AssemblerExtensions.Move(asm, argument.StoreValue, argument.CallingValue);

            asm->CallRel32(entryPoint - routineStubOffset);

            // epilogue
            epilogueAddress = asm->GetCurrentAddress();
            asm->WriteInIntLabelOffset(return1Label, epilogueAddress);

            asm
            ->AddRsp32(stack.MaxStack)
            ->PopRdi()
            ->PopRbp()
            ->Ret();
        }

        void PrepareRedirection()
        {
            var method = methodStatement.NativeCodePointer;
            var asm = (Assembler*)&method;
            asm->JmpRel32Ptr(indirect.Address);

            // for beauty 😊
            asm->Nop(originalPrologueBytes.Length - 6);
        }

        public override string ToString() => "{ " + string.Join(", ",
            "Routine: " + Convert.ToString((long)stubRoutine.Address, 16)
        ) + " }";
    }
}