using Korn.Utils.Memory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace Korn.Hooking
{
    public unsafe class MethodAllocator : IDisposable
    {
        const int RoutineRegionAllocationSize = 0x10000;
        const int IndirectRegionAllocationSize = 0x1000;

        static bool isInitialized;
        static MethodAllocator instance;
        public static MethodAllocator Instance 
        {
            get
            {
                if (!isInitialized)
                {
                    isInitialized = true;
                    instance = new MethodAllocator();
                }
                return instance;
            }
        }

        MethodAllocator()
        {
            regionAllocator = new RegionAllocator();
            caveFinder = new CaveFinder();
            routineRegionAllocator = new RoutineRegionAllocator(regionAllocator);
            indirectRegionAllocator = new IndirectRegionAllocator(regionAllocator, caveFinder);
        }

        RegionAllocator regionAllocator;
        CaveFinder caveFinder;
        RoutineRegionAllocator routineRegionAllocator;
        IndirectRegionAllocator indirectRegionAllocator;

        public AllocatedMethod AllocateMethod(byte[] routineBytes)
        {
            fixed (byte* routineBytesPointer = routineBytes)
                return AllocateMethod(routineBytesPointer, routineBytes.Length);
        }

        public AllocatedMethod AllocateMethod(byte* routineBytesPointer, int routineBytesCount)
        {
            var routine = CreateRoutine(routineBytesPointer, routineBytesCount);
            var method = new AllocatedMethod(indirectRegionAllocator, routine);
            return method;
        }

        RoutinesRegion.Routine CreateRoutine(byte[] routineBytes)
        {
            fixed (byte* routineBytesPointer = routineBytes)
                return CreateRoutine(routineBytesPointer, routineBytes.Length);
        }

        RoutinesRegion.Routine CreateRoutine(byte* routineBytesPointer, int routineBytesCount)
        {
            var routine = routineRegionAllocator.CreateRoutine(routineBytesPointer, routineBytesCount);
            return routine;
        }

        public void Dispose()
        {
            regionAllocator.Dispose();
        }

        ~MethodAllocator() => Dispose();

        public class AllocatedMethod : IDisposable
        {
            public AllocatedMethod(IndirectRegionAllocator indirectRegionAllocator, RoutinesRegion.Routine routine)
            {
                this.indirectRegionAllocator = indirectRegionAllocator;
                Routine = routine;
            }

            public RoutinesRegion.Routine Routine { get; private set; }
            public List<IndirectsRegion.Indirect> Indirects { get; private set; } = new List<IndirectsRegion.Indirect>();
            IndirectRegionAllocator indirectRegionAllocator;

            public IndirectsRegion.Indirect CreateIndirect(IntPtr fromAddress)
            {
                var indirect = indirectRegionAllocator.CreateIndirect(fromAddress, Routine.Address);
                Indirects.Add(indirect);
                return indirect;
            }

            public void Dispose()
            {
                Routine.Dispose();

                foreach (var indirect in Indirects)
                    indirect.Dispose();
            }
        }

        public class IndirectRegionAllocator
        {
            public IndirectRegionAllocator(RegionAllocator regionAllocator, CaveFinder caveFinder)
            {
                this.regionAllocator = regionAllocator;
                this.caveFinder = caveFinder;
            }

            List<IndirectsRegion> regions = new List<IndirectsRegion>();
            RegionAllocator regionAllocator;
            CaveFinder caveFinder;

            public IndirectsRegion.Indirect CreateIndirect(IntPtr nearTo, IntPtr indirectAddress)
            {
                var region = GetIndirectsRegion(nearTo);
                var indirect = region.CreateIndirect(indirectAddress);
                return indirect;
            }

            IndirectsRegion GetIndirectsRegion(IntPtr nearTo)
            {
                foreach (var region in regions)
                {
                    if (region.MemoryRegion.IsNearTo(nearTo))
                        if (region.HasFreeIndirectSlot)
                            return region;
                }

                return CreateIndirectRegion(nearTo);
            }

            IndirectsRegion CreateIndirectRegion(IntPtr nearTo)
            {
                var memoryRegion = FindMemoryRegion();
                var region = new IndirectsRegion(memoryRegion);
                return region;

                MemoryRegion FindMemoryRegion()
                {
                    var allocatedRegion = regionAllocator.AllocateNearMemory(nearTo, IndirectRegionAllocationSize);
                    if (allocatedRegion != null)
                        return allocatedRegion;

                    var caveRegion = caveFinder.FindMemoryCave(nearTo);
                    return caveRegion;
                }
            }
        }

        public class RoutineRegionAllocator
        {
            public RoutineRegionAllocator(RegionAllocator regionAllocator)
            {
                this.regionAllocator = regionAllocator;
            }

            List<RoutinesRegion> regions = new List<RoutinesRegion>();
            RegionAllocator regionAllocator;

            public RoutinesRegion.Routine CreateRoutine(byte[] routineBytes)
            {
                fixed (byte* routineBytesPointer = routineBytes)
                    return CreateRoutine(routineBytesPointer, routineBytes.Length);
            }

            public RoutinesRegion.Routine CreateRoutine(byte* routineBytes, int routineSize)
            {
                var region = GetRoutinesRegion(routineSize);
                return region.AddRoutine(routineBytes, routineSize);
            }

            RoutinesRegion GetRoutinesRegion(int requestedSize)
            {
                foreach (var region in regions)
                    if (region.HasSpaceForNewRoutine(requestedSize))
                        return region;

                return CreateRoutinesRegion();
            }

            RoutinesRegion CreateRoutinesRegion()
            {
                var memoryRegion = regionAllocator.AllocateMemory(RoutineRegionAllocationSize);

                var region = new RoutinesRegion(memoryRegion);
                regions.Add(region);
                return region;
            }
        }

        public class RegionAllocator : IDisposable
        {
            List<MemoryRegion.Allocated> regions = new List<MemoryRegion.Allocated>();

            public MemoryRegion.Allocated AllocateMemory(long size)
            {
                var mbi = MemoryAllocator.Allocate(size);
                var region = MemoryRegion.Allocated.Descriptor.From(&mbi);
                var managedBlob = MemoryRegion.Allocated.From(region);
                regions.Add(managedBlob);

                return managedBlob;
            }

            public MemoryRegion.Allocated AllocateNearMemory(IntPtr address, long size)
            {
                var mbi = MemoryAllocator.AllocateNear(address, size);
                if (!mbi.IsValid)
                    return null;

                var region = MemoryRegion.Allocated.Descriptor.From(&mbi);
                var managedBlob = MemoryRegion.Allocated.From(region);
                regions.Add(managedBlob);

                return managedBlob;
            }

            public void Dispose()
            {
                foreach (var region in regions)
                    region.Dispose();
            }
        }

        public class CaveFinder
        {
            List<MemoryRegion.Caved> regions = new List<MemoryRegion.Caved>();

            public MemoryRegion.Caved GetFreeCaveNear(IntPtr address, out bool isNewCave)
            {
                var regions = this.regions.Count();
                var cave = GetFreeCaveNear(address);
                isNewCave = this.regions.Count() != regions;
                return cave;
            }

            public MemoryRegion.Caved GetFreeCaveNear(IntPtr address)
            {
                foreach (var cave in regions)
                    if (cave.IsNearTo(address))
                        if (!cave.IsNoSpace)
                            return cave;

                return FindMemoryCave(address);
            }

            public MemoryRegion.Caved FindMemoryCave(IntPtr address)
            {
                var mbi = MemoryAllocator.Query(address);

                MemoryRegion.Caved freeCave;
                do freeCave = FindFreeCaveNear(address, & mbi);
                while (freeCave.IsNoSpace);

                return freeCave;
            }

            MemoryRegion.Caved FindFreeCaveNear(IntPtr address, MemoryBaseInfo* mbi)
            {
                var cave = FindFreeCaveNearTop(address, mbi);
                if (cave == null)
                    cave = FindFreeCaveNearBot(address, mbi);
                if (cave == null)
                    throw new InvalidOperationException(
                        "Korn.Hooking.MethodAllocator: " +
                        "There are no free regions or caves to allocate memory for hooking funtionality, the arrow struck Achilles' heel 😞"
                    );

                return cave;
            }

            MemoryRegion.Caved FindFreeCaveNearTop(IntPtr address, MemoryBaseInfo* startMbi)
            {
                if (!IsCaveFound(startMbi) && IsSuitForCave(startMbi))
                    return BuildCaveBlobFromFreeCave(startMbi);

                MemoryBaseInfo mbi = MemoryAllocator.QueryNextTop(startMbi);
                while ((long)startMbi->BaseAddress > 0x10000 && AddressSpaceUtils.IsRegionNearToAddress(&mbi, address))
                {
                    if (!IsCaveFound(&mbi) && IsSuitForCave(&mbi))
                        return BuildCaveBlobFromFreeCave(&mbi);

                    mbi = MemoryAllocator.QueryNextTop(&mbi);
                }

                return null;
            }

            MemoryRegion.Caved FindFreeCaveNearBot(IntPtr address, MemoryBaseInfo* startMbi)
            {
                if (!IsCaveFound(startMbi) && IsSuitForCave(startMbi))
                    return BuildCaveBlobFromFreeCave(startMbi);

                MemoryBaseInfo mbi = MemoryAllocator.QueryNextBot(startMbi);
                while ((long)startMbi->BaseAddress > 0x10000 && AddressSpaceUtils.IsRegionNearToAddress(&mbi, address))
                {
                    if (!IsCaveFound(&mbi) && IsSuitForCave(&mbi))
                        return BuildCaveBlobFromFreeCave(&mbi);

                    mbi = MemoryAllocator.QueryNextBot(&mbi);
                }

                return null;
            }

            MemoryRegion.Caved BuildCaveBlobFromFreeCave(MemoryBaseInfo* mbi)
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
                return new MemoryRegion.Caved(mbi->BaseAddress, (IntPtr)start, size);

                int CountLastZeroBytes(IntPtr address)
                {
                    var pointer = (byte*)address;
                    while (*pointer-- == 0) ;
                    return (int)((long)address - (long)pointer + 1);
                }
            }

            bool IsSuitForCave(MemoryBaseInfo* mbi) => mbi->Type == MemoryType.Image;

            bool IsCaveFound(MemoryBaseInfo* mbi)
            {
                foreach (var blob in regions)
                    if (blob.RegionBase == mbi->BaseAddress)
                        return true;
                return false;
            }
        }

        public class IndirectsRegion : IDisposable
        {
            public IndirectsRegion(MemoryRegion memoryRegion)
            {
                MemoryRegion = memoryRegion;
                statusStorage = new StatusStorage(this);
            }

            public MemoryRegion MemoryRegion { get; private set; }
            List<Indirect> indirects = new List<Indirect>();
            StatusStorage statusStorage;

            public Indirect CreateIndirect(IntPtr indiretAddress)
            {
                var index = statusStorage.GetFreeStatusIndex();
                if (index == -1) 
                    throw new InvalidOperationException(
                        "Korn.Hooking.MethodAllocator.IndirectsRegion->CreateIndirect: " + 
                        "Bad check for free indirect slots. There are no free slots in this region"
                    );

                var indirect = statusStorage.CreateIndirect(index);
                *indirect.IndirectAddress = indiretAddress;
                indirects.Add(indirect);
                return indirect;
            }

            public void RemoveIndirect(Indirect indirect)
            {
                statusStorage.RemoveIndirect(indirect);
                indirects.Remove(indirect);

                indirect.Dispose();
            }

            public bool HasFreeIndirectSlot => statusStorage.HasFreeStatusSlot;

            public void Dispose()
            {
                foreach (var indirect in indirects)
                    indirect.Dispose();
            }

            public class Indirect : IDisposable
            {
                public Indirect(IndirectsRegion indirectsRegion, IntPtr address) => (IndirectsRegion, Address) = (indirectsRegion, address);

                public IndirectsRegion IndirectsRegion { get; private set; }
                public IntPtr Address { get; private set; }

                public IntPtr* IndirectAddress => (IntPtr*)Address;
                public int IndirectIndex;

                bool disposed;
                public void Dispose()
                {
                    if (disposed)
                        return;
                    disposed = true;

                    *IndirectAddress = IntPtr.Zero;
                    IndirectsRegion.RemoveIndirect(this);
                }
            }

            public class StatusStorage : IDisposable
            {
                public StatusStorage(IndirectsRegion region)
                {
                    this.region = region;

                    var bytes = region.MemoryRegion.Size;
                    var statuses = bytes / sizeof(long);
                    var longs = (statuses + 63) / 64;
                    AllocateLongs(longs);

                    this.statuses = statuses;
                }

                int statuses;
                IndirectsRegion region;
                long[] longs;
                GCHandle longsHandle;
                long* longsPointer;

                public StatusEnum this[int index]
                {
                    get => (StatusEnum)(longsPointer[index / 64] & (1L << (index % 64)));
                    set => longsPointer[index / 64] =
                       value == StatusEnum.Free
                       ? (longsPointer[index / 64] & ~(1L << (index % 64)))
                       : (longsPointer[index / 64] | (1L << (index % 64)));
                }

                public StatusEnum GetStatusByAddress(IntPtr address) => this[(int)((long)address - (long)region.MemoryRegion.Address) / sizeof(IntPtr)];
                public IntPtr GetAddressByIndex(int index) => region.MemoryRegion.Address + index * sizeof(IntPtr);

                public bool HasFreeStatusSlot => GetFreeStatusIndex() != -1;

                public Indirect CreateIndirect(int index)
                {
                    var address = GetAddressByIndex(index);
                    var indirect = new Indirect(region, address);
                    indirect.IndirectIndex = index;
                    this[index] = StatusEnum.Reserved;

                    UpdateNoSpaceState();
                    return indirect;
                }

                public void RemoveIndirect(Indirect indirect)
                {
                    var index = indirect.IndirectIndex;
                    this[index] = StatusEnum.Free;
                    indirect.Dispose();

                    UpdateNoSpaceState(false);
                }

                void UpdateNoSpaceState() => UpdateNoSpaceState(HasFreeStatusSlot);
                void UpdateNoSpaceState(bool noSpace)
                {
                    if (region.MemoryRegion is MemoryRegion.Caved cavedMemoryRegion)
                        cavedMemoryRegion.IsNoSpace = noSpace;
                }

                public int GetFreeStatusIndex()
                {
                    for (var hi = 0; hi < statuses / 64; hi++)
                        if (longs[hi] != 1 << 64)
                            for (var li = 0; li < 64; li++)
                            {
                                var index = hi * 64 + li;
                                if (this[index] == StatusEnum.Free)
                                    return index;
                            }

                    for (var index = statuses / 64 * 64; index < statuses; index++)
                        if (this[index] == StatusEnum.Free)
                            return index;

                    return -1;
                }

                void AllocateLongs(int longsCount)
                {
                    longs = new long[longsCount];
                    longsHandle = GCHandle.Alloc(longsCount, GCHandleType.Pinned);
                    longsPointer = (long*)longsHandle.AddrOfPinnedObject();
                }

                public void Dispose() => longsHandle.Free();

                public enum StatusEnum : byte
                {
                    Free = 0,
                    Reserved = 1
                }
            }
        }

        public class RoutinesRegion : IDisposable
        {
            public RoutinesRegion(MemoryRegion.Allocated allocatedMemory) => AllocatedMemory = allocatedMemory;

            public MemoryRegion.Allocated AllocatedMemory { get; private set; }
            List<Routine> routines = new List<Routine>();

            public Routine AddRoutine(byte[] routineBytes)
                => AddRoutine(GetOffsetForInsertRoutine(routineBytes.Length), routineBytes);
            public Routine AddRoutine(int offset, byte[] routineBytes)
            {
                fixed (byte* routineBytesPointer = routineBytes)
                    return AddRoutine(offset, routineBytesPointer, routineBytes.Length);
            }

            public Routine AddRoutine(byte* routineBytes, int routinLength)
                => AddRoutine(GetOffsetForInsertRoutine(routinLength), routineBytes, routinLength);
            public Routine AddRoutine(int offset, byte* routineBytes, int routinLength)
            {
                var address = AllocatedMemory.Address + offset;
                Buffer.MemoryCopy(routineBytes, (byte*)address, routinLength, routinLength);

                var routine = new Routine(this, offset, address, routinLength);
                AddRoutine(routine);
                return routine;
            }

            // adds a routine to the list, so that the offsets are in order
            public void AddRoutine(Routine routine)
            {
                int index = 0;
                for (var i = 0; i < routines.Count; i++)
                    if (routines[i].RegionOffset > routine.RegionOffset)
                        index = i;

                routines.Insert(index, routine);
            }

            public void RemoveRoutine(Routine routine)
            {
                var removed = routines.Remove(routine);
                if (!removed)
                    return;

                routine.Dispose();
            }

            public bool HasSpaceForNewRoutine(int requestedSize) => GetOffsetForInsertRoutine(requestedSize) != -1;

            public int GetOffsetForInsertRoutine(int size)
            {
                var regionSize = AllocatedMemory.Size;

                if (routines.Count == 0)
                    return regionSize > size ? 0 : -1;

                var firstRoutine = routines[0];
                if (firstRoutine.RegionOffset >= size)
                    return 0;

                var lastRoutine = routines.Last();
                if (lastRoutine.RegionOffset + lastRoutine.Size + size < regionSize)
                    return lastRoutine.RegionOffset + lastRoutine.Size;

                for (var i = 0; i < routines.Count - 1; i++)
                {
                    var currentRoutine = routines[i];
                    var nextRoutine = routines[i + 1];
                    var nextHRoutineOffset = currentRoutine.RegionOffset + currentRoutine.Size + size;
                    if (nextHRoutineOffset <= nextRoutine.RegionOffset)
                        return nextHRoutineOffset;
                }

                return -1;
            }

            public void Dispose() => AllocatedMemory.Dispose();

            public unsafe class Routine : IDisposable
            {
                public Routine(RoutinesRegion routinesRegion, int regionOffset, IntPtr address, int size)
                    => (RoutinesRegion, RegionOffset, Address, Size) = (routinesRegion, regionOffset, address, size);

                public RoutinesRegion RoutinesRegion { get; private set; }
                public int RegionOffset { get; private set; }
                public IntPtr Address { get; private set; }
                public int Size { get; private set; }

                public void ZeroMemory()
                {
                    var longLength = Size / sizeof(long);
                    var longPointer = (long*)Address;
                    for (var i = 0; i < longLength; i++)
                        *longPointer++ = 0;

                    var byteLength = Size % sizeof(byte);
                    var bytePointer = (byte*)longPointer;
                    for (var i = 0; i < byteLength; i++)
                        *bytePointer++ = 0;
                }

                bool disposed;
                public void Dispose()
                {
                    if (disposed)
                        return;
                    disposed = true;

                    ZeroMemory();
                    RoutinesRegion.RemoveRoutine(this);
                }
            }
        }

        public abstract class MemoryRegion
        {
            public MemoryRegion(IntPtr address, int size) => (Address, Size) = (address, size);

            public IntPtr Address { get; private set; }
            public int Size { get; private set; }

            public bool IsNearTo(IntPtr address) => AddressSpaceUtils.IsRegionNearToAddress(Address, Size, address);

            public class Caved : MemoryRegion
            {
                public readonly IntPtr RegionBase;

                public bool IsNoSpace;

                public Caved(IntPtr regionBase, IntPtr address, int size) : base(address, size)
                    => RegionBase = regionBase;
            }

            public class Allocated : MemoryRegion, IDisposable
            {
                Allocated(Descriptor regionDescriptor) : base(regionDescriptor.Address, regionDescriptor.Size)
                    => RegionDescriptor = regionDescriptor;

                public Descriptor RegionDescriptor;

                public void Free() => MemoryAllocator.Free(RegionDescriptor.Address, RegionDescriptor.Size);

                public static Allocated From(Descriptor regionDescriptor) => new Allocated(regionDescriptor);
                public static Allocated From(MemoryBaseInfo* mbi) => From(Descriptor.From(mbi));

                bool disposed;
                public void Dispose()
                {
                    if (disposed)
                        return;
                    disposed = true;

                    Free();
                }
                ~Allocated() => Dispose();

                public unsafe struct Descriptor
                {
                    Descriptor(IntPtr address, int size) => (Address, Size) = (address, size);

                    public readonly IntPtr Address;
                    public readonly int Size;

                    public static Descriptor From(MemoryBaseInfo* mbi) => new Descriptor(mbi->BaseAddress, (int)mbi->RegionSize);
                }
            }
        }
    }

    public unsafe static class AddressSpaceUtils
    {
        public static bool IsRegionNearToAddress(MemoryBaseInfo* mbi, IntPtr nearTo)
            => IsRegionNearToAddress(mbi->BaseAddress, mbi->RegionSize, nearTo);

        public static bool IsRegionNearToAddress(IntPtr regionAddress, long regionSize, IntPtr nearTo) => 
            (long)regionAddress > (long)nearTo
            ? (long)regionAddress - (long)nearTo - regionSize < 0x7FFFFFF0
            : (long)nearTo - (long)regionAddress < 0x7FFFFFF0;
    }
}