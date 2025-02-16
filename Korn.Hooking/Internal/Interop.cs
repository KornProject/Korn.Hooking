using System;
using System.Runtime.InteropServices;

static unsafe class Interop
{
    const string kernel = "kernel32";

    [DllImport(kernel, CharSet = CharSet.Unicode)] public static extern
        IntPtr GetModuleHandle([MarshalAs(UnmanagedType.LPWStr)] string moduleName);
}