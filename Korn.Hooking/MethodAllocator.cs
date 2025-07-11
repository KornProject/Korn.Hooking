﻿using System.Collections.Generic;
using Korn.Modules.Algorithms;
using Korn.Utils;
using System;
using Korn.Modules.WinApi.Kernel;
using Korn.Logger;

namespace Korn.Hooking
{
    public unsafe class MethodAllocator : IDisposable
    {
        const int RoutineRegionAllocationSize = 0x10000;
        const int ArraysRegionAllocationSize = 0x10000;
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
            routineRegionAllocator = new Routine.Region.Allocator(regionAllocator);
            indirectRegionAllocator = new Indirect.Region.Allocator(regionAllocator);
        }

        RegionAllocator regionAllocator;
        Routine.Region.Allocator routineRegionAllocator;
        Indirect.Region.Allocator indirectRegionAllocator;

        public Indirect CreateIndirect(IntPtr nearTo) => indirectRegionAllocator.CreateIndirect(nearTo);

        public Routine CreateRoutine(byte[] routineBytes)
        {
            fixed (byte* routineBytesPointer = routineBytes)
                return CreateRoutine(routineBytesPointer, routineBytes.Length);
        }

        public Routine CreateRoutine(byte* routineBytesPointer, int routineBytesCount) 
            => routineRegionAllocator.CreateRoutine(routineBytesPointer, routineBytesCount);

        public Routine CreateAllocatedRoutine(int initialSize) 
            => routineRegionAllocator.CreateRoutine(initialSize);

        public void Dispose() => regionAllocator.Dispose();

        ~MethodAllocator() => Dispose();

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

        public class Indirect : IDisposable
        {
            public Indirect(Region indirectsRegion, IntPtr address) => (IndirectsRegion, Address) = (indirectsRegion, address);

            public Region IndirectsRegion { get; private set; }
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

            public class Region : IDisposable
            {
                public Region(MemoryRegion memoryRegion)
                {
                    MemoryRegion = memoryRegion;
                    statusStorage = new StatusStorage(this);
                }

                public MemoryRegion MemoryRegion { get; private set; }
                List<Indirect> indirects = new List<Indirect>();
                StatusStorage statusStorage;

                public Indirect CreateIndirect()
                {
                    if (!statusStorage.HasFreeEntry)
                        throw new KornError(
                            "Korn.Hooking.MethodAllocator.IndirectsRegion->CreateIndirect: " +
                            "Bad check for free indirect slots. There are no free slots in this region"
                        );

                    var indirect = statusStorage.CreateIndirect();
                    indirects.Add(indirect);
                    return indirect;
                }

                public void RemoveIndirect(Indirect indirect)
                {
                    statusStorage.RemoveIndirect(indirect);
                    indirects.Remove(indirect);

                    indirect.Dispose();
                }

                public bool HasFreeIndirectSlot => statusStorage.HasFreeEntry;

                public void Dispose()
                {
                    foreach (var indirect in indirects)
                        indirect.Dispose();
                }

                public class StatusStorage : StateCollection
                {
                    public StatusStorage(Region region) : base(region.MemoryRegion.Size / sizeof(long)) => this.region = region;

                    Region region;

                    public bool GetStatusByAddress(IntPtr address) => this[(int)((long)address - (long)region.MemoryRegion.Address) / sizeof(IntPtr)];
                    public IntPtr GetAddressByIndex(int index) => region.MemoryRegion.Address + index * sizeof(IntPtr);

                    public Indirect CreateIndirect()
                    {
                        var index = HoldEntry();
                        var address = GetAddressByIndex(index);
                        var indirect = new Indirect(region, address) { IndirectIndex = index };

                        return indirect;
                    }

                    public void RemoveIndirect(Indirect indirect) => FreeEntry(indirect.IndirectIndex);
                }

                public class Allocator
                {
                    public Allocator(RegionAllocator regionAllocator)
                    {
                        this.regionAllocator = regionAllocator;
                    }

                    List<Region> regions = new List<Region>();
                    RegionAllocator regionAllocator;

                    public Indirect CreateIndirect(IntPtr nearTo)
                    {
                        var region = GetIndirectsRegion(nearTo);
                        var indirect = region.CreateIndirect();
                        return indirect;
                    }

                    Region GetIndirectsRegion(IntPtr nearTo)
                    {
                        while (true)
                        {
                            foreach (var region in regions)
                            {
                                if (region.MemoryRegion.IsNearTo(nearTo))
                                    if (region.HasFreeIndirectSlot)
                                        return region;
                            }

                            CreateIndirectRegion(nearTo);
                        }
                    }

                    Region CreateIndirectRegion(IntPtr nearTo)
                    {
                        var memoryRegion = FindMemoryRegion();
                        var region = new Region(memoryRegion);
                        regions.Add(region);
                        return region;

                        MemoryRegion FindMemoryRegion()
                        {
                            var allocatedRegion = regionAllocator.AllocateNearMemory(nearTo, IndirectRegionAllocationSize);
                            if (allocatedRegion != null)
                                return allocatedRegion;

                            throw new Exception($"MemoryAllocator: No regions near to memory 0x{nearTo.ToHexString()}");
                        }
                    }
                }
            }
        }

        public unsafe class Routine : BlockPlacementCollection.Block, IDisposable
        {
            public Routine(Region routinesRegion, int regionOffset, IntPtr address, int size) : base(regionOffset, size)
                => (RoutinesRegion, Address) = (routinesRegion, address);

            public Region RoutinesRegion { get; private set; }
            public IntPtr Address { get; private set; }

            bool disposed;
            public void Dispose()
            {
                if (disposed)
                    return;
                disposed = true;

                Memory.Zero((void*)Address, Size);
                RoutinesRegion.RemoveRoutine(this);
            }

            public class Region : BlockPlacementCollection.Region<Routine>, IDisposable
            {
                public Region(MemoryRegion.Allocated allocatedMemory) : base(allocatedMemory.Size) => AllocatedMemory = allocatedMemory;

                public MemoryRegion.Allocated AllocatedMemory { get; private set; }

                public Routine AddRoutine(BlockPlacementCollection.AddRequest request, byte[] routineBytes)
                {
                    fixed (byte* routineBytesPointer = routineBytes)
                        return AddRoutine(request, routineBytesPointer);
                }

                public Routine AddRoutine(BlockPlacementCollection.AddRequest request, byte* routineBytes)
                {
                    var routine = AddRoutine(request);
                    Memory.Copy(routineBytes, (byte*)routine.Address, request.Size);
                    return routine;
                }

                public Routine AddRoutine(BlockPlacementCollection.AddRequest request)
                {
                    var address = AllocatedMemory.Address + request.Offset;
                    var routine = AddBlock(request, (offset, size) => new Routine(this, offset, address, size));
                    return routine;
                }

                public void RemoveRoutine(Routine routine) => RemoveBlock(routine);

                public void Dispose() => AllocatedMemory.Dispose();

                public class Allocator
                {
                    public Allocator(RegionAllocator regionAllocator)
                    {
                        this.regionAllocator = regionAllocator;
                    }

                    List<Region> regions = new List<Region>();
                    RegionAllocator regionAllocator;

                    public Routine CreateRoutine(byte[] routineBytes)
                    {
                        fixed (byte* routineBytesPointer = routineBytes)
                            return CreateRoutine(routineBytesPointer, routineBytes.Length);
                    }

                    public Routine CreateRoutine(byte* routineBytes, int routineSize)
                    {
                        var (region, request) = RequestRoutineAdd(routineSize);
                        return region.AddRoutine(request, routineBytes);
                    }

                    public Routine CreateRoutine(int size)
                    {
                        var (region, request) = RequestRoutineAdd(size);
                        return region.AddRoutine(request);
                    }

                    (Region region, BlockPlacementCollection.AddRequest request) RequestRoutineAdd(int requestedSize)
                    {
                        while (true)
                        {
                            foreach (var region in regions)
                            {
                                var request = region.RequestAddBlock(requestedSize);
                                if (request.HasSpace)
                                    return (region, request);
                            }

                            CreateRoutinesRegion();
                        }
                    }

                    Region CreateRoutinesRegion()
                    {
                        var memoryRegion = regionAllocator.AllocateMemory(RoutineRegionAllocationSize);

                        var region = new Region(memoryRegion);
                        regions.Add(region);
                        return region;
                    }
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

                public Caved(IntPtr regionBase, IntPtr address, int size) : base(address, size)
                    => RegionBase = regionBase;
            }

            public class Allocated : MemoryRegion, IDisposable
            {
                Allocated(Descriptor regionDescriptor) : base(regionDescriptor.Address, regionDescriptor.Size)
                    => RegionDescriptor = regionDescriptor;

                public Descriptor RegionDescriptor;

                public void Free() => MemoryAllocator.Free(RegionDescriptor.Address);

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

                    public static Descriptor From(MemoryBaseInfo* mbi) => new Descriptor((IntPtr)mbi->BaseAddress, (int)mbi->RegionSize);
                }
            }
        }
    }

    public unsafe static class AddressSpaceUtils
    {
        public static bool IsRegionNearToAddress(MemoryBaseInfo* mbi, IntPtr nearTo)
            => IsRegionNearToAddress((IntPtr)mbi->BaseAddress, mbi->RegionSize, nearTo);

        public static bool IsRegionNearToAddress(IntPtr regionAddress, long regionSize, IntPtr nearTo) => 
            (long)regionAddress > (long)nearTo
            ? (long)regionAddress - (long)nearTo - regionSize < 0x7FFFFFF0
            : (long)nearTo - (long)regionAddress < 0x7FFFFFF0;
    }
}