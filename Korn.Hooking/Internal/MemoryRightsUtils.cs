static unsafe class MemoryRightsUtils
{
    const int PAGE_EXECUTE_READ = 0x20;
    const int PAGE_EXECUTE_READWRITE = 0x40;

    public static void RemoveRightsRestrictionsFromModule(string moduleName)
    {
        var moduleHandle = Interop.GetModuleHandle(moduleName);
        MBI mbi;
        mbi.BaseAddress = moduleHandle;
        do
        {
            Interop.VirtualQuery(mbi.BaseAddress, &mbi);
            Interop.VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE);
        } 
        while (!((mbi.Protect == PAGE_EXECUTE_READ && mbi.RegionSize == 0x1000) || mbi.Protect == PAGE_EXECUTE_READWRITE));
    }

    public static void RemoveRightsRestrionsFromAddress(nint address)
    {
        MBI mbi;
        Interop.VirtualQuery(address, &mbi);
        Interop.VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE);
    }
}