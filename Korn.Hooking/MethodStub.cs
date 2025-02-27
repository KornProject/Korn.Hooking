using System.Collections.Generic;
using Korn.Utils.Assembler;
using System.Reflection;
using System;
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
        // in the future handle ref ref arg's

        /*
         * 
         * rbp - temp register
         * rdi - hook address
         * r10:general - temp storing hook calling result
         * 
        */
        void WriteRoutineCode(byte** pointer_code)
        {
            var stack = new Stack(methodInfo);
            stack.SetInitialPrevStackStartOffset(-0x10 /* push: rbp rdi */);
            var methodStack = stack.BuildMethodStack();

            var epilogueAddress = IntPtr.Zero;

            var entryPoint = *(IntPtr*)pointer_code;
            var asm = (Assembler*)pointer_code;

            // prologue
            asm
            ->PushRbp()
            ->PushRdi()
            ->SubRsp32(stack.MaxStack)
            ->MovRdi64(hooksArray.RootNode);

            foreach (var argument in methodStack.Arguments)
            {
                Move(argument.InputValue, argument.StoreValue);
                MovePointer(argument.StoreValue, argument.PointerToStoreValue);
            }

            if (methodStack.HasReturnType)
            {
                var returnType = methodStack.ReturnType;
                var stackValue = returnType.StoreValue as Stack.StackValue;
                var offset = stackValue.Offset;

                asm
                ->XorRbpRbp()
                ->MovRspPtrOff32Rbp(offset);

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
            ->PopRbp()
            ->PopRdi()
            ->Ret();

            void MoveRax(Stack.Value from)
            {
                if (from is Stack.StackValue stackValue)
                    MoveRaxStack(stackValue);
                else if (from is Stack.RegisterValue registerValue)
                    MoveRaxRegister(registerValue);
            }

            void MoveRaxStack(Stack.StackValue value) => asm->MovRaxRspPtrOff32(value.Offset);

            void MoveRaxRegister(Stack.RegisterValue value)
            {
                var register = value.Register;
                switch (register)
                {
                    case Stack.ArgumentRegister.Rcx:
                        asm->MovRaxRcx();
                        break;
                    case Stack.ArgumentRegister.Rdx:
                        asm->MovRaxRdx();
                        break;
                    case Stack.ArgumentRegister.R8:
                        asm->MovRaxR8();
                        break;
                    case Stack.ArgumentRegister.R9:
                        asm->MovRaxR9();
                        break;
                }
            }

            void Move(Stack.Value from, Stack.Value to)
            {
                if (from is Stack.RegisterValue fromRegisterValue)
                {
                    if (to is Stack.StackValue toStackValue)
                        MoveRegisterToStack(fromRegisterValue, toStackValue);
                    else ThrowNotImpemented();
                }
                else if (from is Stack.StackValue fromStackValue)
                {
                    if (to is Stack.RegisterValue toRegisterValue)
                        MoveStackToRegister(fromStackValue, toRegisterValue);
                    else if (to is Stack.StackValue toStackValue)
                        MoveStackToStack(fromStackValue, toStackValue);
                }
                else ThrowNotImpemented();
            }

            void MovePointer(Stack.Value from, Stack.Value to)
            {
                if (from is Stack.StackValue fromStackValue && to is Stack.StackValue toStackValue)
                    MovePointerStackToStack(fromStackValue, toStackValue);
                else ThrowNotImpemented();
            }

            void MoveRegisterToStack(Stack.RegisterValue from, Stack.StackValue to)
            {
                var register = from.Register;
                var offset = to.Offset;
                switch (register)
                {
                    case Stack.ArgumentRegister.Rcx:
                        asm->MovRspPtrOff32Rcx(to.Offset);
                        break;
                    case Stack.ArgumentRegister.Rdx:
                        asm->MovRspPtrOff32Rdx(to.Offset);
                        break;
                    case Stack.ArgumentRegister.R8:
                        asm->MovRspPtrOff32R8(to.Offset);
                        break;
                    case Stack.ArgumentRegister.R9:
                        asm->MovRspPtrOff32R9(to.Offset);
                        break;
                }
            }

            void MoveStackToStack(Stack.StackValue from, Stack.StackValue to)
            {
                asm->MovRbpRspPtrOff32(from.Offset);
                asm->MovRspPtrOff32Rbp(to.Offset);
            }

            void MovePointerStackToStack(Stack.StackValue from, Stack.StackValue to)
            {
                asm->MovRbpRsp();

                if (from.Offset >= 0)
                    asm->AddRbp32(from.Offset);
                else asm->SubRbp32(-from.Offset);

                if (to.Offset >= 0)
                    asm->MovRspPtrOff32Rbp(to.Offset);
                else asm->MovRspPtrOff32Rbp(-to.Offset);
            }

            void MoveStackToRegister(Stack.StackValue from, Stack.RegisterValue to)
            {
                var offset = from.Offset;
                var register = to.Register;
                switch (register)
                {
                    case Stack.ArgumentRegister.Rcx:
                        asm->MovRcxPspPtrOff32(offset);
                        break;
                    case Stack.ArgumentRegister.Rdx:
                        asm->MovRdxPspPtrOff32(offset);
                        break;
                    case Stack.ArgumentRegister.R8:
                        asm->MovR8PspPtrOff32(offset);
                        break;
                    case Stack.ArgumentRegister.R9:
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
            var method = methodStatement.MethodPointer;
            var asm = (Assembler*)&method;
            asm->JmpRel32Ptr(indirect.Address);
        }

        class Stack
        {
            const int ClrRoutineStackOffset = 0x20;

            public Stack(MethodInfo method)
            {
                Method = method;

                HasReturnType = method.ReturnType != typeof(void);
                ArgumentsCount = method.GetParameters().Length;
                ParamsCount = ArgumentsCount + (HasReturnType ? 1 : 0);
            }

            public readonly MethodInfo Method;
            public readonly bool HasReturnType;
            public readonly int ArgumentsCount;
            public readonly int ParamsCount;

            // should be negative
            public int InitialPrevStackOffset { get; private set; }

            int lastCalculatedMaxStack = -1;
            public int MaxStack => lastCalculatedMaxStack == -1 ? (lastCalculatedMaxStack = CalculateMaxStack()) : lastCalculatedMaxStack;

            public void SetInitialPrevStackStartOffset(int offset) => InitialPrevStackOffset = offset;

            int CalculateMaxStack()
            {
                var value = (ParamsCount * 2 * 0x08) + (ParamsCount > 4 ? ((ParamsCount - 4) * 2 * 0x08) : 0) + ClrRoutineStackOffset;
                if ((value + InitialPrevStackOffset) % 0x10 == 0)
                    value += 0x08;
                return value;
            }

            public int GetOffsetForPrevStack(int index) => InitialPrevStackOffset - MaxStack - index * 0x08 - 0x08/*call return address*/;
            public int GetOffsetForStartStack(int index) => ClrRoutineStackOffset + index * 0x08;
            public int GetOffsetForEndStack(int index) => MaxStack - index * 0x08 - 0x08;

            public MethodStack BuildMethodStack() => new MethodStack(this);

            public class MethodStack
            {
                public MethodStack(Stack stack)
                {
                    var method = stack.Method;
                    var arguments = method.GetParameters().Length;
                    for (var argumentIndex = 0; argumentIndex < arguments; argumentIndex++)
                    {
                        var argument = new Argument(stack, argumentIndex);
                        Arguments.Add(argument);
                        Parameters.Add(argument);
                    }

                    if (method.ReturnType != typeof(void))
                    {
                        HasReturnType = true;

                        var parameterIndex = arguments;
                        ReturnType = new Argument(stack, parameterIndex);
                        Parameters.Add(ReturnType);
                    }
                }

                public readonly List<Argument> Arguments = new List<Argument>();
                public readonly List<Argument> Parameters = new List<Argument>();

                public readonly bool HasReturnType;
                public readonly Argument ReturnType;
            }

            public class Argument
            {
                public Argument(Stack stack, int index)
                {
                    if (index <= 3)
                    {
                        var register = (ArgumentRegister)Enum.GetValues(typeof(ArgumentRegister)).GetValue(index);
                        InputValue = new RegisterValue(register);
                        CallingValue = new RegisterValue(register);
                    }
                    else
                    {
                        InputValue = new StackValue(stack.GetOffsetForPrevStack(index - 4));
                        CallingValue = new StackValue(stack.GetOffsetForStartStack(index - 4));
                    }

                    StoreValue = new StackValue(stack.GetOffsetForEndStack(index * 2));
                    PointerToStoreValue = new StackValue(stack.GetOffsetForEndStack(index * 2 + 1));
                }

                public Value InputValue;
                public Value StoreValue;
                public Value PointerToStoreValue;
                public Value CallingValue;
            }

            public abstract class Value { }

            public class StackValue : Value
            {
                public StackValue(int offset) => Offset = offset;
                public int Offset;
            }

            public class RegisterValue : Value
            {
                public RegisterValue(ArgumentRegister register) => Register = register;
                public ArgumentRegister Register;
            }

            public enum ArgumentRegister
            {
                Rcx,
                Rdx,
                R8,
                R9
            }
        }       
    }
}