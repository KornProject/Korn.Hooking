using System.Collections.Generic;
using System.Linq;

namespace Korn.Hooking.Algorithms
{
    public class BlockPlacementCollection
    {
        public class Region<TBlock> where TBlock : Block
        {
            public Region(int regionSize) => RegionSize = regionSize;

            public int RegionSize;
            public readonly List<TBlock> Blocks = new List<TBlock>();

            public delegate TBlock BlockCtor(int offset, int size);

            public AddRequest RequestAddBlock(int size)
            {
                var offset = GetSpaceOffsetForBlock(size);
                var request = new AddRequest
                {
                    Offset = offset,
                    Size = size
                };

                return request;
            }

            int GetSpaceOffsetForBlock(int requestedSpace)
            {
                if (RegionSize < requestedSpace)
                    return -1;

                if (Blocks.Count == 0)
                    return 0;

                var block = Blocks[0];
                if (block.Offset >= requestedSpace)
                    return 0;

                for (var i = 1; i < Blocks.Count; i++)
                    if (Blocks[i].Offset - block.Offset - block.Size >= requestedSpace)
                        return block.Offset + block.Size;
                    else block = Blocks[i];

                block = Blocks.Last();
                if (RegionSize - block.Offset - block.Size >= requestedSpace)
                    return block.Offset + block.Size;

                return -1;
            }

            public TBlock AddBlock(AddRequest request, BlockCtor ctor)
            {
                if (!request.HasSpace)
                    throw new KornError(
                        "Korn.Hooking.Algorithms.BlockPlacementCollection.Region->AddBlock",
                        "Called AddBlock with no space request.",
                        "It is necessary to process has space logic outside the AddBlock method."
                    );

                var block = ctor(request.Offset, request.Size);
                AppendBlock(block);
                return block;
            }

            void AppendBlock(TBlock block)
            {
                var index = 0;
                for (var i = 0; i < Blocks.Count; i++, index++)
                    if (Blocks[i].Offset > block.Offset)
                        break;

                Blocks.Insert(index, block);
            }
        }

        public struct AddRequest
        {
            public int Offset;
            public int Size;
            public bool HasSpace => Offset != -1;
        }

        public class Block
        {
            public Block(int offset, int size) => (Offset, Size) = (offset, size);

            public readonly int Offset;
            public int Size;
        }
    }
}