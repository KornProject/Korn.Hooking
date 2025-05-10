using System.Runtime.CompilerServices;
using System.Collections.Generic;
using System.Reflection;
using System.Linq;
using Korn.Utils;
using System;

namespace Korn.Hooking
{
    public unsafe abstract class MethodStatement
    {
        static List<MethodStatement> ExistsMethodStatements = new List<MethodStatement>();

        private protected MethodStatement(MethodInfo method)
        {
            Method = method;
            Handle = method.MethodHandle;

            PrepareMethod();
            EnsureMethodIsCompiled();
            EnsureMemoryRegionIsAccessible(NativeCodePointer);
        }

        public readonly MethodInfo Method;
        public readonly RuntimeMethodHandle Handle;
        public IntPtr DelegatePointer => Handle.GetFunctionPointer();
        public IntPtr NativeCodePointer { get; internal set; } // may be null if method is not compiled
        public bool HasNativeCode => NativeCodePointer != IntPtr.Zero;
        public bool IsCompiled { get; internal set; }

        void PrepareMethod() => PrepareMethod(Handle);

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

        static MethodStatement CreateMethodStatement(MethodInfo method)
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

        public static void PrepareMethod(MethodInfo method) => PrepareMethod(method);
        public static void PrepareMethod(RuntimeMethodHandle handle) => RuntimeHelpers.PrepareMethod(handle);
    }
}