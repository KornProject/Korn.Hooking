using Korn.Utils;
using System;
using System.Collections.Generic;

unsafe static class MethodStubHandleAllocator
{
    static List<Region> regions = new List<Region>();

    public static MethodStubHandle* AllocateFor(void* entryPoint)
    {
        var region = GetSuitableRegionFor(entryPoint);
        return region.AllocateHandle();
    }

    static Region GetSuitableRegionFor(void* entryPoint)
    {
        foreach (Region region in regions)
        {
            if (!region.CanAllocateHandle)
                continue;

            if (region.IsSuitableFor(entryPoint))
                return region;
        }

        return Region.AllocateFor(entryPoint);
    }

    struct Region
    {
        public const int RegionSize = 0x1000;

        Region(IntPtr address) => (this.address, lastHoldIndex) = (address, -1);

        IntPtr address;
        int lastHoldIndex;

        public bool CanAllocateHandle => lastHoldIndex != RegionSize / sizeof(MethodStubHandle) - 1;

        public MethodStubHandle* AllocateHandle()
        {
            var index = ++lastHoldIndex;
            var address = this.address + index * sizeof(MethodStubHandle);
            return (MethodStubHandle*)address;
        }

        public bool IsSuitableFor(void* entryPoint) => IsSuitableFor(address, entryPoint);

        public static bool IsSuitableFor(IntPtr address, void* entryPoint)
        {
            var offset = (long)address - (long)entryPoint;
            if (offset > 0)
                offset += RegionSize;

            return Math.Abs(offset) < 0x7FFFFFF0;
        }

        public static Region AllocateFor(void* entryPoint)
        {
            var mbi = MemoryAllocator.AllocateNear((IntPtr)entryPoint, RegionSize);
            if (mbi.BaseAddress == default)
                throw new Exception($"MethodStubHandleAllocator.Region->AllocateFor: There is no free space near to address 0x{((IntPtr)entryPoint).ToHexString()} 🥺😥😓😭😭😭");

            return new Region(mbi.BaseAddress);
        }
    }
}