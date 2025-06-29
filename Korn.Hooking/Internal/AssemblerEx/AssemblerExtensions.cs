using Korn;
using System;

unsafe static class AssemblerExtensions
{
    public static void MoveRax(Assembler* asm, MemoryValue from)
    {
        if (from is StackValue stackValue)
            MoveRaxStack(asm, stackValue);
        else if (from is RegisterValue registerValue)
            MoveRaxRegister(asm, registerValue);
    }

    public static void MoveRaxStack(Assembler* asm, StackValue value) => asm->MovRaxRspPtrOff32(value.Offset);

    public static void MoveRaxRegister(Assembler* asm, RegisterValue value)
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

    public static void Move(Assembler* asm, MemoryValue from, MemoryValue to)
    {
        if (from is RegisterValue fromRegisterValue)
        {
            if (to is StackValue toStackValue)
                MoveRegisterToStack(asm, fromRegisterValue, toStackValue);
            else throw new NotImplementedException();
        }
        else if (from is StackValue fromStackValue)
        {
            if (to is RegisterValue toRegisterValue)
                MoveStackToRegister(asm, fromStackValue, toRegisterValue);
            else if (to is StackValue toStackValue)
                MoveStackToStack(asm, fromStackValue, toStackValue);
        }
        else throw new NotImplementedException();
    }

    public static void MovePointer(Assembler* asm, MemoryValue from, MemoryValue to)
    {
        if (from is StackValue fromStackValue && to is StackValue toStackValue)
            MovePointerStackToStack(asm, fromStackValue, toStackValue);
        else throw new NotImplementedException();
    }

    public static void MoveRegisterToStack(Assembler* asm, RegisterValue from, StackValue to)
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

    public static void MoveStackToStack(Assembler* asm, StackValue from, StackValue to)
    {
        asm->MovR11RspPtrOff32(from.Offset);
        asm->MovRspPtrOff32R11(to.Offset);
    }

    public static void MoveStackToRegister(Assembler* asm, StackValue from, RegisterValue to)
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

    public static void MovePointerStackToStack(Assembler* asm, StackValue from, StackValue to)
    {
        asm->MovR11Rsp();

        if (from.Offset >= 0)
            asm->AddR1132(from.Offset);
        else asm->SubR1132(-from.Offset);

        if (to.Offset >= 0)
            asm->MovRspPtrOff32R11(to.Offset);
        else asm->MovRspPtrOff32R11(-to.Offset);
    }
}