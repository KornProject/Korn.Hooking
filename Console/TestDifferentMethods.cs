using Korn.ClrJit;
using Korn.Hooking;
using Korn.Utils;
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime;
using System.Runtime.CompilerServices;
using System.Threading;

static unsafe class TestDifferentMethods
{
    static Type T = typeof(TestDifferentMethods);

    static MethodInfo methodof(Delegate @delegate) => @delegate.Method;

    public static void Execute()
    {        
        var i = new Instance();

        Stopwatch stopwatch = Stopwatch.StartNew();
        stopwatch.Start();
        MethodStatement.CompileMethodsAsync(
            methodof((Action<object>)Console.WriteLine),
            methodof(DiffArgs),
            methodof(DiffArgsRet),
            methodof(MuchArgs),
            methodof(i.MuchArgs),
            methodof(InnerStrangeCode),
            methodof(StressTest),

            methodof(hk_ConsoleWriteLine),
            methodof(hk_DiffArgs),
            methodof(hk_DiffArgsRet),
            methodof(hk_MuchArgs),
            methodof(hk_InstanceMuchArgs),
            methodof(hk_InnerStrangeCode),
            methodof(hk_StressTest)
        );

        stopwatch.Stop();
        Console.WriteLine($"{stopwatch.ElapsedMilliseconds}ms");

        Thread.Sleep(500);



        ConsoleWriteLine();
        Console.WriteLine();
        StaticDiffArgs();
        Console.WriteLine();
        StaticDiffArgsRet();
        Console.WriteLine();
        StaticMuchArgs();
        Console.WriteLine();
        InstanceMuchArgs();
        Console.WriteLine();
        StaticInnerStrangeCode();
        Console.WriteLine();
        StaticStress();
        Console.WriteLine();

        Console.ReadLine();

        void ConsoleWriteLine()
        {
            var hook = MethodHook.Create((Action<object>)Console.WriteLine).AddEntry(hk_ConsoleWriteLine).Enable();

            Console.WriteLine((object)3);
            Console.WriteLine((object)4L);
            Console.WriteLine((object)"smth");

            hook.Disable();

            Console.WriteLine((object)"Hook disabled");

            hook.Enable();

            Console.WriteLine((object)"Hook enabled");

            hook.Disable();

            Console.WriteLine((object)"Hook finally disabled");
        }

        void StaticDiffArgs()
        {
            var hook = MethodHook.Create((Action<bool, int, string>)DiffArgs).AddEntry(hk_DiffArgs).Enable();

            DiffArgs(true, 10, "ab");
            DiffArgs(false, 10, "ab");
        }

        void StaticDiffArgsRet()
        {
            var hook = MethodHook.Create((Func<bool, int, string, string>)DiffArgsRet).AddEntry(hk_DiffArgsRet).Enable();

            Console.WriteLine(DiffArgsRet(true, 10, "ab"));
            Console.WriteLine(DiffArgsRet(false, 10, "ab"));
        }

        void StaticMuchArgs()
        {
            var hook = MethodHook.Create((Func<bool, int, int, int, int, int, string>)MuchArgs).AddEntry(hk_MuchArgs).Enable();

            Console.WriteLine(MuchArgs(true, 0, 10, 100, 1000, 10000));
            Console.WriteLine(MuchArgs(false, 0, 10, 100, 1000, 10000));
        }

        void InstanceMuchArgs()
        {
            var instance = new Instance();

            var hook = MethodHook.Create((Func<bool, int, int, int, int, int, string>)instance.MuchArgs).AddEntry(hk_InstanceMuchArgs).Enable();

            Console.WriteLine(instance.MuchArgs(true, 0, 10, 100, 1000, 10000));
            Console.WriteLine(instance.MuchArgs(false, 0, 10, 100, 1000, 10000));
        }

        void StaticInnerStrangeCode()
        {
            var hook = MethodHook.Create((Action<int, int, int>)InnerStrangeCode).AddEntry(hk_InnerStrangeCode).Enable();

            InnerStrangeCode(10, 20, 33);
        }

        void StaticStress()
        {            
            var hook = MethodHook.Create((Action<int, int>)StressTest).AddEntry(hk_StressTest).Enable();

            //Console.WriteLine(Convert.ToString((long)hook.DEBUG_Stub.DEBUG_StubRoutine.Address, 16));
            //Console.WriteLine($"{hook.DEBUG_Stub.DEBUG_MethodStatement.DelegatePointer:X} {hook.DEBUG_Stub.DEBUG_MethodStatement.NativeCodePointer:X} {hook.DEBUG_Stub.DEBUG_StubRoutine.Address:X}");
            //Console.ReadLine();

            for (var i = 0; i < 1000; i++)
            {
                StressTest(i, i);
            }
        }
    }

    static bool hk_ConsoleWriteLine(ref object obj)
    {
        if (obj is int)
        {
            obj = $"INTEGER: {obj}";
        }
        else if (obj is long)
        {
            Console.WriteLine($"CS CWL LONG: {obj}");
            return false;
        }
        else
        {
            obj = $"str: {obj}";
        }

        return true;
    }

    static void DiffArgs(bool a, int b, string c)
    {
        Console.WriteLine($"og: {a} {b} {c}");
    }

    static bool hk_DiffArgs(ref bool a, ref int b, ref string c)
    {
        Console.WriteLine($"hk: {a} {b} {c}");
        b += 1;
        c += "z";
        return a;
    }

    static string DiffArgsRet(bool a, int b, string c)
    {
        var str = $"{a} {b} {c}";
        Console.WriteLine("og:" + str);
        return str;
    }

    static bool hk_DiffArgsRet(ref bool a, ref int b, ref string c, ref string result)
    {
        Console.WriteLine($"hk: {a} {b} {c}");
        b += 1;
        c += "z";
        result = "zzz";
        return a;
    }

    static string MuchArgs(bool a, int b, int c, int d, int e, int f)
    {
        var str = $"{a} {b} {c} {d} {e} {f}";
        Console.WriteLine("og:" + str);
        return str;
    }

    static bool hk_MuchArgs(ref bool a, ref int b, ref int c, ref int d, ref int e, ref int f, ref string result)
    {
        b += 1;
        c += 2;
        d += 4;
        e += 8;
        f += 16;
        var str = $"{a} {b} {c} {d} {e} {f}";

        result = str + "z";
        Console.WriteLine("hk:" + str);
        return a;
    }

    static bool hk_InstanceMuchArgs(ref Instance instance, ref bool a, ref int b, ref int c, ref int d, ref int e, ref int f, ref string result)
    {
        b += 1;
        c += 2;
        d += 4;
        e += 8;
        f += 16;
        var str = $"{a} {b} {c} {d} {e} {f}";

        result = str + "z";
        Console.WriteLine("hk:" + str);
        return a;
    }

    class Instance
    {
        public string MuchArgs(bool a, int b, int c, int d, int e, int f)
        {
            var str = $"{a} {b} {c} {d} {e} {f}";
            Console.WriteLine("og:" + str);
            return str;
        }
    }

    static void InnerStrangeCode(int a, int b, int c)
    {
        Console.WriteLine($"{a} {b} {c}");
    }

    static unsafe bool hk_InnerStrangeCode(ref int a, ref int b, ref int c)
    {
        a += 1;
        b += 2;
        c += 3;

        try
        {
            var fileName = "test.txt";
            File.WriteAllText(fileName, "text");

            var bytes = stackalloc byte[120];
            bytes[10] = 0x20;
            c += bytes[2];
        } 
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }

        return true;
    }

    static int stressCounter;
    [MethodImpl(MethodImplOptions.NoInlining)]
    static void StressTest(int a, int b)
    {
        Console.WriteLine(a + b); 
        Console.WriteLine(++stressCounter);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    static bool hk_StressTest(ref int a, ref int b)
    {
        Console.WriteLine(a + b); 
        stressCounter++;
        return true;
    }
}