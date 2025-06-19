using Korn;
using Korn.Utils;
using System;

unsafe static class MethodAsmCodeDetermination
{
    internal static class Precode
    {
        public static bool IsIt(IntPtr address)
        {
            var dasm = (Disassembler*)&address;

            if (dasm->IsLengthChangingInstruction)
                dasm->SkipLengthChangingInstruction();

            return
                dasm->IsJmpPtrRel32Instruction &&
                dasm->NextInstruction()->IsMov10PtrInstruction &&
                dasm->NextInstruction()->IsJmpPtrRel32Instruction;
        }

        public static int GetRedirectOffset(IntPtr address) => ((Disassembler*)&address)->GetJmpPtrRel32Offset();

        public static IntPtr GetRedirectAddress(IntPtr address) => ((Disassembler*)&address)->GetJmpPtrRel32Operand();
    }

    internal static class TieredCompilationCounter
    {
        public static bool IsIt(IntPtr address)
        {
            var dasm = (Disassembler*)&address;

            return
                dasm->IsMovRaxRel32PtrInstruction &&
                dasm->NextInstruction()->IsDecPtrRaxInstruction &&
                dasm->NextInstruction()->IsJeRel8Instruction && dasm->GetJeRel8Offset() == 0x06;
        }

        public static IntPtr GetRedirectAddress(IntPtr address) =>
            ((Disassembler*)&address)
            ->SkipInstructions(3)
            ->GetJmpPtrRel32Operand();

        public static void NopCounter(IntPtr address) =>
            ((Assembler*)&address)
            ->NopInstructions(3)
            // mov rax, […]
            // dec [rax]
            // je <JMP.&OnCallCountThresholdReachedStub>
            ->NextInstruction() // jmp […]
            ->NopInstruction(); // jmp [<&OnCallCountThresholdReachedStub>]
    }
}