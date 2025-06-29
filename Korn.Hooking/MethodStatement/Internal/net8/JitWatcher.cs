using System.Runtime.CompilerServices;
using System.Threading;
using Korn.Shared;
using System;
using Korn.Hooking;

static class JitWatcher
{
    // > Ich sage Hallo zu millu98 von onlyfans und Col-e von recaf.
    static void A() { }

    static JitWatcher()
    {
#if NET472
        return;
#endif
        var thread = new Thread(Body) { Name = "Korn TieredCompilation Watcher" };
        thread.Start();
        KornShared.Logger.WriteMessage($"Started watcher thread with ID {thread.ManagedThreadId}");
    }

    static JitWatcherMethodPool methodPool = new JitWatcherMethodPool();

    public static void AddMethodToQueue(MethodStatement method)
    {
        methodPool.Add(method);
    }

    static void Body()
    {
        var hasTieredCompilation = CheckTieredCompilation();
        if (hasTieredCompilation)
            KornShared.Logger.WriteMessage("Environment has Tiered Compilation feature.");

        var index = -1;
        while (true)
        {
            var count = methodPool.Count;
            if (count == 0)
            {
                Thread.Sleep(2);
                continue;
            }

            index++;
            if (index >= count)
                index = 0;

            var method = methodPool[index];
            var pointer = method.DelegatePointer;

            if (!MethodAsmCodeDetermination.Precode.IsIt(pointer))
            {
                method.NativeCodePointer = pointer;
                if (!hasTieredCompilation)
                {
                    Finalize();
                }
                continue;
            }

            if (MethodAsmCodeDetermination.Precode.GetRedirectOffset(pointer) == 0x06)
                continue;

            pointer = MethodAsmCodeDetermination.Precode.GetRedirectAddress(pointer);
            if (!MethodAsmCodeDetermination.TieredCompilationCounter.IsIt(pointer))
            {
                method.NativeCodePointer = pointer;
                if (!hasTieredCompilation)
                {
                    Finalize();
                }
                continue;
            }

            method.NativeCodePointer = MethodAsmCodeDetermination.TieredCompilationCounter.GetRedirectAddress(pointer);
            MethodStatement.EnsureMemoryRegionIsAccessible(pointer);
            MethodAsmCodeDetermination.TieredCompilationCounter.NopCounter(pointer);
            KornShared.Logger.WriteMessage($"Disabled jit counter for method {method.Method.Name}");

            Finalize();

            void Finalize()
            {
                method.IsCompiled = true;
                methodPool.Remove(method);
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

            if (!MethodAsmCodeDetermination.Precode.IsIt(pointer))
                continue;

            if (MethodAsmCodeDetermination.Precode.GetRedirectOffset(pointer) == 0x06)
                continue;

            pointer = MethodAsmCodeDetermination.Precode.GetRedirectAddress(pointer);

            if (!MethodAsmCodeDetermination.TieredCompilationCounter.IsIt(pointer))
                continue;

            return true;
        }

        return false;
    }
}