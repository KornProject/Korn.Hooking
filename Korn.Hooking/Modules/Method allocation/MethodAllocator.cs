using Korn.Utils.Memory;
using System;
using System.Collections.Generic;

namespace Korn.Hooking
{
    public unsafe class MethodAllocator : IDisposable
    {
        List<CaveMemoryBlob> foundCaveBlobs = new List<CaveMemoryBlob>();
        List<MemoryBlob> storeBlobs = new List<MemoryBlob>();
        List<AllocatedMemoryBlob> codeBlobs = new List<AllocatedMemoryBlob>();

        public void EnsureAllocationToReach(IntPtr address)
        {
            foreach (var blob in storeBlobs)
                if (Math.Abs((long)blob.Address - (long)address) < 0xFFFFFFF0)
                    if (blob.FreeSpace >= sizeof(IntPtr))
                        return;

            var nearBlob = AllocateNearMemory(address, 0x1000);
            if (nearBlob == null)
            {
                var caveBlob = FindMemoryCave(address);
                foundCaveBlobs.Add(caveBlob);
                return;
            }

            storeBlobs.Add(nearBlob);
        }
        
        AllocatedMemoryBlob AllocateMemory(long size)
        {
            var mbi = MemoryAllocator.Allocate(size);
            var region = AllocatedMemoryRegion.From(&mbi); 
            var managedBlob = AllocatedMemoryBlob.From(region);
            return managedBlob;
        }

        AllocatedMemoryBlob AllocateNearMemory(IntPtr address, long size)
        {
            var mbi = MemoryAllocator.AllocateNear(address, size);
            if (!mbi.IsValid)
                return null;

            var region = AllocatedMemoryRegion.From(&mbi);
            var managedBlob = AllocatedMemoryBlob.From(region);
            return managedBlob;
        }

        CaveMemoryBlob FindMemoryCave(IntPtr address)
        {
            var mbi = MemoryAllocator.Query(address);

            CaveMemoryBlob freeCave;
            do freeCave = FindFreeCaveNear(&mbi);
            while (freeCave.FreeSpace >= sizeof(IntPtr));

            return freeCave;
        }

        CaveMemoryBlob FindFreeCaveNear(MemoryBaseInfo* mbi)
        {
            var cave = FindFreeCaveNearTop(mbi);
            if (cave == null)
                cave = FindFreeCaveNearBot(mbi);
            if (cave == null)
                throw new InvalidOperationException(
                    "Korn.Hooking.MethodAllocator: " +
                    "There are no free regions or caves to allocate memory for hooking funtionality, the arrow struck Achilles' heel 😞"
                );

            return cave;
        }

        CaveMemoryBlob FindFreeCaveNearTop(MemoryBaseInfo* startMbi)
        {
            if (!IsCaveFound(startMbi) && IsSuitForCave(startMbi))
                return BuildCaveBlobFromFreeCave(startMbi);

            MemoryBaseInfo mbi = MemoryAllocator.QueryNextTop(startMbi);
            while ((long)startMbi->BaseAddress > 0x10000)
            {
                if (!IsCaveFound(&mbi) && IsSuitForCave(&mbi))
                    return BuildCaveBlobFromFreeCave(&mbi);

                mbi = MemoryAllocator.QueryNextTop(&mbi);
            }

            return null;
        }

        CaveMemoryBlob FindFreeCaveNearBot(MemoryBaseInfo* startMbi)
        {
            if (!IsCaveFound(startMbi) && IsSuitForCave(startMbi))
                return BuildCaveBlobFromFreeCave(startMbi);

            MemoryBaseInfo mbi = MemoryAllocator.QueryNextBot(startMbi);
            while ((long)startMbi->BaseAddress > 0x10000)
            {
                if (!IsCaveFound(&mbi) && IsSuitForCave(&mbi))
                    return BuildCaveBlobFromFreeCave(&mbi);

                mbi = MemoryAllocator.QueryNextBot(&mbi);
            }

            return null;
        }

        CaveMemoryBlob BuildCaveBlobFromFreeCave(MemoryBaseInfo* mbi)
        {
            var isExecutable = 
                mbi->Protect.HasFlag(MemoryProtect.Execute) || 
                mbi->Protect.HasFlag(MemoryProtect.ExecuteRead) || // usual case
                mbi->Protect.HasFlag(MemoryProtect.ExecuteReadWrite) ||
                mbi->Protect.HasFlag(MemoryProtect.ExecuteWriteCopy);

            var size = CountLastZeroBytes((IntPtr)((long)mbi->BaseAddress + mbi->RegionSize - 1));
            size -= 8; // prevent the use of memory used by an instruction
            // size may be negative, this region will be added to the used regions, but will not actually be used

            var start = (long)mbi->BaseAddress + mbi->RegionSize - size;
            return new CaveMemoryBlob(mbi->BaseAddress, (IntPtr)start, size);

            int CountLastZeroBytes(IntPtr address)
            {
                var pointer = (byte*)address;
                while (*pointer-- == 0);
                return (int)((long)address - (long)pointer + 1);
            }
        }

        bool IsSuitForCave(MemoryBaseInfo* mbi) => mbi->Type == MemoryType.Image;

        bool IsCaveFound(MemoryBaseInfo* mbi)
        {
            foreach (var blob in foundCaveBlobs)
                if (blob.RegionBase == mbi->BaseAddress)
                    return true;
            return false;
        }

        public void Dispose()
        {
            foreach (var blob in storeBlobs)
                if (blob is AllocatedMemoryBlob allocatedBlob)
                    allocatedBlob.Dispose();
        }

        ~MethodAllocator() => Dispose();
    }

    public unsafe class NearMemoryBlob
    {


        public MemoryBlob Memory { get; private set; }
    }

    public unsafe class CodeMemoryBlob
    {


        public AllocatedMemoryBlob AllocatedMemory { get; private set; }
    }

    public abstract class MemoryBlob
    {
        public MemoryBlob(IntPtr address, int size)
        {
            Address = address;
            Size = size;
        }

        public readonly IntPtr Address;
        public readonly int Size;

        public int Offset { get; private protected set; }

        public int FreeSpace => Size - Offset;
    }

    public unsafe class CaveMemoryBlob : MemoryBlob
    {
        public readonly IntPtr RegionBase;

        public CaveMemoryBlob(IntPtr regionBase, IntPtr address, int size) : base(address, size)
            => RegionBase = regionBase;


        public IntPtr ReserveMemory(int size)
        {
            var address = (IntPtr)((long)Address + (long)RegionBase);

            if (Offset + size > Size)
                throw new InvalidOperationException($"Korn.Hooking.CaveMemoryBlob->ReserveMemory: Requested too much memory. Requested: {size}, Free: {FreeSpace}");

            Offset += size;
            return address;
        }
    }

    public unsafe class AllocatedMemoryBlob : MemoryBlob, IDisposable
    {
        AllocatedMemoryBlob(AllocatedMemoryRegion memoryRegion) : base(memoryRegion.Address, memoryRegion.Size) { }

        public AllocatedMemoryRegion RegionData;

        public static AllocatedMemoryBlob From(AllocatedMemoryRegion memoryRegion) => new AllocatedMemoryBlob(memoryRegion);
        
        public void Dispose() => MemoryAllocator.Free(RegionData.Address, RegionData.Size);
        ~AllocatedMemoryBlob() => Dispose();
    }

    public unsafe struct AllocatedMemoryRegion
    {
        AllocatedMemoryRegion(IntPtr address, int size)
        {
            Address = address;
            Size = size;
        }

        public readonly IntPtr Address;
        public readonly int Size;

        public static AllocatedMemoryRegion From(MemoryBaseInfo* mbi) => new AllocatedMemoryRegion(mbi->BaseAddress, (int)mbi->RegionSize);
    }
}