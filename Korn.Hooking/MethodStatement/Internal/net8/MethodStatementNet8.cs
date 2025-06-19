using System.Runtime.CompilerServices;
using System.Collections.Generic;
using System.Reflection;
using System.Threading;
using Korn.Shared;
using Korn.Utils;
using System;
using Korn.Hooking;

#pragma warning disable CS0162 // Unreachable code detected
// for .net7+
unsafe class MethodStatementNet8 : MethodStatement
{
    static MethodStatementNet8() => RuntimeHelpers.RunClassConstructor(typeof(JitWatcher).TypeHandle);

    public MethodStatementNet8(MethodInfo method) : base(method) { }

    private protected override void EnsureMethodIsCompiled()
    {
        if (IsCompiled)
            return;

        JitWatcher.AddMethodToQueue(this);

        while (!HasNativeCode)
            Thread.Sleep(1);
    }        
}
