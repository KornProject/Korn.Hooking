using static Korn.Hooking.MethodAllocator;
using Korn.Utils.Assembler;
using System.Reflection;
using System;
using Korn.Utils.Algorithms;

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
            const int JmpRel32PointerSize = 6;

            var length = Disassembler.CalculateMinInstructionLength((byte*)method, JmpRel32PointerSize);
            var bytes = Utils.Memory.Read(method, length);
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
                Move(argument.InputValue, argument.StoreValue);
                MovePointer(argument.StoreValue, argument.PointerToStoreValue);
            }

            if (methodStack.HasReturnType)
            {
                var returnType = methodStack.ReturnType;
                var stackValue = returnType.StoreValue as StackValue;
                var offset = stackValue.Offset;

                asm
                ->XorR11R11()
                ->MovRspPtrOff32R11(offset);

                MovePointer(returnType.StoreValue, returnType.PointerToStoreValue);
            }

            // entry
            var func_getNode = asm->GetCurrentAddress();
            asm->MovRaxRdiPtr();

            foreach (var argument in methodStack.Parameters)            
                Move(argument.PointerToStoreValue, argument.CallingValue);

            asm->CallRax();

            // checking calling result
            if (methodStack.HasReturnType)
            {
                asm->MovR10Rax();
                MoveRax(methodStack.ReturnType.StoreValue);
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
                Move(argument.StoreValue, argument.CallingValue);

            asm->CallRel32(entryPoint - routineStubOffset);

            // epilogue
            epilogueAddress = asm->GetCurrentAddress();
            asm->WriteInIntLabelOffset(return1Label, epilogueAddress);

            asm
            ->AddRsp32(stack.MaxStack)
            ->PopRdi()
            ->PopRbp()
            ->Ret();

            void MoveRax(MemoryValue from)
            {
                if (from is StackValue stackValue)
                    MoveRaxStack(stackValue);
                else if (from is RegisterValue registerValue)
                    MoveRaxRegister(registerValue);
            }

            void MoveRaxStack(StackValue value) => asm->MovRaxRspPtrOff32(value.Offset);

            void MoveRaxRegister(RegisterValue value)
            {
                var register = value.Register;
                switch (register)
                {
                    case ArgumentRegister.Rcx:
                        asm->MovRaxRcx();
                        break;
                    case ArgumentRegister.Rdx:
                        asm->MovRaxRdx();
                        break;
                    case ArgumentRegister.R8:
                        asm->MovRaxR8();
                        break;
                    case ArgumentRegister.R9:
                        asm->MovRaxR9();
                        break;
                }
            }

            void Move(MemoryValue from, MemoryValue to)
            {
                if (from is RegisterValue fromRegisterValue)
                {
                    if (to is StackValue toStackValue)
                        MoveRegisterToStack(fromRegisterValue, toStackValue);
                    else ThrowNotImpemented();
                }
                else if (from is StackValue fromStackValue)
                {
                    if (to is RegisterValue toRegisterValue)
                        MoveStackToRegister(fromStackValue, toRegisterValue);
                    else if (to is StackValue toStackValue)
                        MoveStackToStack(fromStackValue, toStackValue);
                }
                else ThrowNotImpemented();
            }

            void MovePointer(MemoryValue from, MemoryValue to)
            {
                if (from is StackValue fromStackValue && to is StackValue toStackValue)
                    MovePointerStackToStack(fromStackValue, toStackValue);
                else ThrowNotImpemented();
            }

            void MoveRegisterToStack(RegisterValue from, StackValue to)
            {
                var register = from.Register;
                var offset = to.Offset;
                switch (register)
                {
                    case ArgumentRegister.Rcx:
                        asm->MovRspPtrOff32Rcx(to.Offset);
                        break;
                    case ArgumentRegister.Rdx:
                        asm->MovRspPtrOff32Rdx(to.Offset);
                        break;
                    case ArgumentRegister.R8:
                        asm->MovRspPtrOff32R8(to.Offset);
                        break;
                    case ArgumentRegister.R9:
                        asm->MovRspPtrOff32R9(to.Offset);
                        break;
                }
            }

            void MoveStackToStack(StackValue from, StackValue to)
            {
                asm->MovR11RspPtrOff32(from.Offset);
                asm->MovRspPtrOff32R11(to.Offset);
            }

            void MovePointerStackToStack(StackValue from, StackValue to)
            {
                asm->MovR11Rsp();

                if (from.Offset >= 0)
                    asm->AddR1132(from.Offset);
                else asm->SubR1132(-from.Offset);

                if (to.Offset >= 0)
                    asm->MovRspPtrOff32R11(to.Offset);
                else asm->MovRspPtrOff32R11(-to.Offset);
            }

            void MoveStackToRegister(StackValue from, RegisterValue to)
            {
                var offset = from.Offset;
                var register = to.Register;
                switch (register)
                {
                    case ArgumentRegister.Rcx:
                        asm->MovRcxPspPtrOff32(offset);
                        break;
                    case ArgumentRegister.Rdx:
                        asm->MovRdxPspPtrOff32(offset);
                        break;
                    case ArgumentRegister.R8:
                        asm->MovR8PspPtrOff32(offset);
                        break;
                    case ArgumentRegister.R9:
                        asm->MovR9PspPtrOff32(offset);
                        break;
                }
            }

            void ThrowNotImpemented()
            {
                throw new KornException(
                    "Korn.Hooking.MethodStub.WriteRoutineCode: ",
                    "Not implemented action for assembler"
                );
            }
        }

        void PrepareRedirection()
        {
            var method = methodStatement.NativeCodePointer;
            var asm = (Assembler*)&method;
            asm->JmpRel32Ptr(indirect.Address);

            // for beauty 😊
            for (var i = 6; i < originalPrologueBytes.Length; i++)
                asm->Nop();
        }

        public override string ToString() => "{ " + string.Join(", ",
            "Routine: " + Convert.ToString((long)stubRoutine.Address, 16)
        ) + " }";
    }
}