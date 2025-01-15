using System.Runtime.InteropServices;

static unsafe class Interop
{
    const string kernel = "kernel32";

    [DllImport(kernel)] static extern
        int VirtualQuery(nint address, MBI* mbi, int size);

    [DllImport(kernel)] static extern
        bool VirtualProtect(nint address, nuint size, uint newProtect, uint* oldProtect);

    [DllImport(kernel, CharSet = CharSet.Unicode)] public static extern
        nint GetModuleHandle([MarshalAs(UnmanagedType.LPWStr)] string moduleName);

    public static void VirtualQuery(nint address, MBI* mbi)
    {
        VirtualQuery(address, mbi, sizeof(MBI));
    }

    public static void VirtualProtect(nint address, long size, uint newProtect)
    {
        uint oldProtect;
        VirtualProtect(address, (nuint)size, newProtect, &oldProtect);
    }
}

[StructLayout(LayoutKind.Sequential)]
struct MBI
{
    public nint BaseAddress;
    public nint AllocationBase;
    public int AllocationProtect;
    int __alignment1;
    public long RegionSize;
    public int State;
    public int Protect;
    public int Type;
    int __alignment2;
}