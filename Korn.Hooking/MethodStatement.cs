using Korn.Shared;
using Korn.Utils.Assembler;
using Korn.Utils.Memory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading;

// If it ever have problems with Jit Tier-1 compilation, it can be added a check for a hook, if the native method doesn't have a hook, throw an exception

namespace Korn.Hooking
{
    public unsafe abstract class MethodStatement
    {
        static List<MethodStatement> ExistsMethodStatements = new List<MethodStatement>();

        private protected MethodStatement(MethodInfo method)
        {
            Method = method;
            Handle = method.MethodHandle;

            RuntimeHelpers.PrepareMethod(Handle);
            EnsureMethodIsCompiled();
            EnsureMemoryRegionIsAccessible(NativeCodePointer);
        }

        public MethodInfo Method { get; private set; }
        public RuntimeMethodHandle Handle { get; private set; }
        public IntPtr DelegatePointer => Handle.GetFunctionPointer();
        public IntPtr NativeCodePointer { get; internal set; } // may be null if method is not compiled
        public bool HasNativeCode => NativeCodePointer != IntPtr.Zero;
        public bool IsCompiled { get; internal set; }

        private protected abstract void EnsureMethodIsCompiled();

        public static MethodStatement From(MethodInfoSummary summary) => From(summary.Method);

        public static MethodStatement From(MethodInfo method)
        {
            lock (ExistsMethodStatements)
            {
                var exists = ExistsMethodStatements.FirstOrDefault(m => m.Method == method);
                if (exists != null)
                    return exists;

                exists = CreateMethodStatement(method);
                ExistsMethodStatements.Add(exists);
                return exists;
            }
        }

        public static MethodStatement CreateMethodStatement(MethodInfo method)
            =>
#if NET8_0
            new MethodStatementNet8(method); 
#elif NET472
            new MethodStatementNet472(method);
#endif

        public static void EnsureMemoryRegionIsAccessible(IntPtr address)
        {
            var mbi = MemoryAllocator.Query(address);
            if (!mbi.Protect.IsWritable())
                mbi.SetProtection(MemoryProtect.ExecuteReadWrite);
        }
    }

    public unsafe class MethodStatementNet472 : MethodStatement
    {
        public MethodStatementNet472(MethodInfo method) : base(method) { }

        private protected override void EnsureMethodIsCompiled()
        {
            var pointer = DelegatePointer;
            var dasm = (Disassembler*)&pointer;

            while (true)
            {
                if (dasm->IsCallRel32Instruction)
                {
                    Thread.Sleep(1);
                    continue;
                }

                if (dasm->IsJmpRel32Instruction)
                    pointer = dasm->GetJmpRel32Operand();

                NativeCodePointer = pointer;
                IsCompiled = true;
                return; 
            }
        }
    }

    // for .net7+
    public unsafe class MethodStatementNet8 : MethodStatement
    {
        static MethodStatementNet8() => RuntimeHelpers.RunClassConstructor(typeof(Watcher).TypeHandle);

        public MethodStatementNet8(MethodInfo method) : base(method) { }

        private protected override void EnsureMethodIsCompiled()
        {
            Watcher.AddToQueue(this);

            while (!HasNativeCode)
                Thread.Sleep(1);
        }

        public static class Watcher
        {
            // > Ich sage Hallo zu millu98 von onlyfans und Col-e von recaf.
            static void A() { }

            static Watcher()
            {
#if NET472
                return;
#endif
                var thread = new Thread(Body) { Name = "Korn.TieredCompilation.Watcher" };
                thread.Start();                
                KornShared.Logger.WriteMessage($"Started watcher thread with ID {thread.ManagedThreadId}");
            }

            static List<MethodStatement> pool = new List<MethodStatement>();
            static void AddToPool(MethodStatement method)
            {
                if (method == null)
                    throw new KornError("Trying to add null-method to method statements pool for watcher.");

                lock (pool)
                    pool.Add(method);
            }

            static void RemoveFromPool(MethodStatement method)
            {
                lock (pool)
                    pool.Remove(method);
            }

            public static void AddToQueue(MethodStatement method) => AddToPool(method);

            static void Body()
            {
                var hasTiredCompilation = CheckTieredCompilation();
                if (hasTiredCompilation)
                    KornShared.Logger.WriteMessage("Environment has Tiered Compilation feature.");

                var index = -1;
                while (true)
                {
                    var count = pool.Count;
                    if (count == 0)
                    {
                        Thread.Sleep(2);
                        continue;
                    }

                    index++;
                    if (index >= count)
                        index = 0;

                    // deletion from the pool performs in only one thread, so we don't have to worry about the index being less than count
                    var method = pool[index];
                    var pointer = method.DelegatePointer;

                    if (!MethodDetermination.Precode.IsIt(pointer))
                    {
                        method.NativeCodePointer = pointer;
                        if (!hasTiredCompilation)
                            Finalize();
                        continue;
                    }

                    if (MethodDetermination.Precode.GetRedirectOffset(pointer) == 0x06)
                        continue;

                    pointer = MethodDetermination.Precode.GetRedirectAddress(pointer);
                    if (!MethodDetermination.TieredCompilationCounter.IsIt(pointer))
                    {
                        method.NativeCodePointer = pointer;
                        if (!hasTiredCompilation)
                            Finalize();
                        continue;
                    }

                    method.NativeCodePointer = MethodDetermination.TieredCompilationCounter.GetRedirectAddress(pointer);
                    EnsureMemoryRegionIsAccessible(pointer);
                    MethodDetermination.TieredCompilationCounter.NopCounter(pointer);
                    KornShared.Logger.WriteMessage($"Disabled jit counter for method {method.Method.Name}");

                    Finalize();

                    void Finalize()
                    {
                        method.IsCompiled = true;
                        RemoveFromPool(method);
                        index--;
                    }
                }                                
            }

            static TimeSpan TieredCompilationTimeout = TimeSpan.FromMilliseconds(500);
            static bool CheckTieredCompilation()
            {
                var method = ((Action)A).Method;
                var methodHandle = method.MethodHandle;
                RuntimeHelpers.PrepareMethod(methodHandle);

                var startTime = DateTime.Now;
                while (DateTime.Now - startTime < TieredCompilationTimeout)
                {
                    Thread.Sleep(1);
                    var pointer = methodHandle.GetFunctionPointer();
                                        
                    if (!MethodDetermination.Precode.IsIt(pointer))
                        continue;

                    if (MethodDetermination.Precode.GetRedirectOffset(pointer) == 0x06)
                        continue;

                    pointer = MethodDetermination.Precode.GetRedirectAddress(pointer);

                    if (!MethodDetermination.TieredCompilationCounter.IsIt(pointer))
                        continue;

                    return true;
                }

                return false;
            }
        }

        public static class MethodDetermination
        {
            public static class Precode
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

            public static class TieredCompilationCounter
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
    }
}