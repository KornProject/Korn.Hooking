using Korn.Shared;
using Korn.Utils.Assembler;
using Korn.Utils.Memory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading;

namespace Korn.Hooking
{
    public unsafe abstract class MethodStatement
    {
        static List<MethodStatement> ExistsMethodStatements = new List<MethodStatement>();

        private protected MethodStatement(MethodInfo method)
        {
            Method = method;
            Handle = method.MethodHandle;
            EnsureMethodIsCompiled();
        }

        public MethodInfo Method { get; private set; }
        public RuntimeMethodHandle Handle { get; private set; }
        public IntPtr DelegatePointer => Handle.GetFunctionPointer();
        public IntPtr NativeCodePointer { get; private protected set; } // may be null if method is not compiled
        public MethodState State { get; private protected set; }

        public abstract void EnsureMethodIsCompiled();

        public bool IsNative() => State == MethodState.Native;
        public bool IsCompiled() => 
            State == MethodState.JitThresholdCounter || 
            State == MethodState.Native || 
            (this is MethodStatementNet8 && MethodStatementNet8.HasTCState && !MethodStatementNet8.HasTC && State == MethodState.TemporaryEntryPoint);
        public bool HaNativeCode() => State != MethodState.NotAssembled;

        public void EnsureNativeCodeIsAccessible()
        {
            var pointer = NativeCodePointer;
            if (pointer == IntPtr.Zero)
                return;

            EnsureMemoryRegionIsAccessible(pointer);
        }

        private protected void EnsureMemoryRegionIsAccessible(IntPtr address)
        {
            var mbi = MemoryAllocator.Query(address);
            if (!mbi.Protect.IsWritable())
                mbi.SetProtection(MemoryProtect.ExecuteReadWrite);
        }

        public static MethodStatement From(MethodInfoSummary summary) => From(summary.Method);

        public static MethodStatement From(MethodInfo method)
        {
            var exists = ExistsMethodStatements.FirstOrDefault(m => m.Method == method);
            if (exists != null)
                return null;

#if NET8_0
            exists = new MethodStatementNet8(method);
#elif NET472
            exists = new MethodStatementNet472(method);
#endif

            ExistsMethodStatements.Add(exists);

            return exists;
        }
    }

    public enum MethodState
    {
        NotAssembled, // no native code assigned to this method
        TemporaryEntryPoint, // .net8 only: has precode with redirect to native code
        JitThresholdCounter, // .net8 only: had precord with redirect to another precode with counting and calling native code
        Native // no precode, method is native
    }

    public unsafe class MethodStatementNet472 : MethodStatement
    {
        public MethodStatementNet472(MethodInfo method) : base(method) { }

        public override void EnsureMethodIsCompiled()
        {
            var pointer = DelegatePointer;
            var dasm = (Disassembler*)&pointer;

            if (dasm->IsCallRel32Instruction)
            {
                NativeCodePointer = pointer;
                State = MethodState.NotAssembled;
                return;
            }

            if (dasm->IsJmpRel32Instruction)
                pointer = dasm->GetJmpRel32Operand();

            NativeCodePointer = pointer;
            State = MethodState.Native;
        }
    }

    // for .net7+
    public unsafe class MethodStatementNet8 : MethodStatement
    {
        // > Ich sage Hallo zu millu98 von onlyfans und Col-e von recaf.
        static void A() { }

        internal static bool HasTCState;
        internal static bool HasTC;
        static MethodStatementNet8()
        {
#if NET472
            return;
#endif
            var method = ((Action)A).Method;
            var methodStatement = new MethodStatementNet8(method);
            HasTC = methodStatement.State == MethodState.JitThresholdCounter;
            HasTCState = true;

            KornShared.Logger.WriteMessage($"Korn.Hooking.MethodStatementNet8->.cctor: Environment has TieredCompilation feature.");
        }

        public MethodStatementNet8(MethodInfo method) : base(method) { }

        public override void EnsureMethodIsCompiled()
        {
            const int threshold = 50;

            if (IsCompiled())
                return;

            RuntimeHelpers.PrepareMethod(Handle);

            var attempts = 0;
            while (attempts++ < threshold)
            {
                var method = DelegatePointer;
                var pointer = method;
                var dasm = (Disassembler*)&pointer;

                if (dasm->IsLengthChangingInstruction)
                    dasm->SkipLengthChangingInstruction();

                if (dasm->IsJmpPtrRel32Instruction &&
                    dasm->NextInstruction()->IsMov10PtrInstruction &&
                    dasm->NextInstruction()->IsJmpPtrRel32Instruction)
                {
                    pointer = method;
                    var innerMethod = dasm->GetJmpPtrRel32Operand();
                    if ((long)innerMethod - (long)method == 0x06)
                    {
                        NativeCodePointer = method;
                        State = MethodState.NotAssembled;

                        Thread.Sleep(1);
                        // it looks like jit is overloaded and hasn't got to the assembling of this method yet
                        continue;
                    }

                    pointer = method = innerMethod;
                    if (dasm->IsMovRaxRel32PtrInstruction &&
                        dasm->NextInstruction()->IsDecPtrRaxInstruction &&
                        dasm->NextInstruction()->IsJeRel8Instruction && dasm->GetJeRel8Offset() == 0x06)
                    {
                        pointer = method;
                        EnsureMemoryRegionIsAccessible(pointer);

                        innerMethod =
                        ((Disassembler*)&pointer)
                        ->SkipInstructions(3)
                        ->GetJmpPtrRel32Operand();

                        pointer = method;
                        ((Assembler*)&pointer)
                        ->NopInstructions(3)
                        // mov rax, […]
                        // dec [rax]
                        // je <JMP.&OnCallCountThresholdReachedStub>
                        ->NextInstruction() // jmp […]
                        ->NopInstruction(); // jmp [<&OnCallCountThresholdReachedStub>]

                        NativeCodePointer = innerMethod;
                        State = MethodState.JitThresholdCounter;
                        KornShared.Logger.WriteMessage($"Korn.Hooking.MethodStatementNet8->EnsureMethodIsCompiled: method compiled after {attempts} attempts.");
                        return;
                    }

                    NativeCodePointer = method;
                    State = MethodState.TemporaryEntryPoint;

                    if (HasTCState && !HasTC)
                        return;

                    Thread.Sleep(5);
                    // it is expected that TemporaryEntryPoint was after NotAssembled and the next state itself will be JitThresholdCounter
                    continue;
                }

                NativeCodePointer = method;
                State = MethodState.Native;
            }

            if (!HasTCState)
                return;

            throw new KornError(
                "Korn.Hooking.MethodStatementNet8.EnsureMethodIsCompiled:",
                "Unable to compile method: timeout"
            );
        }
    }
}