using Region = Korn.Modules.Algorithms.BlockPlacementCollection.Region<Korn.Modules.Algorithms.BlockPlacementCollection.Block>;
using Block = Korn.Modules.Algorithms.BlockPlacementCollection.Block;

class TestFindFreeRoutineSpaceAlgo
{
    public static void Execute()
    {
        var region = new Region(0x1000);

        var request = region.RequestAddBlock(0x88);
        region.AddBlock(request, (offset, size) => new Block(offset, size));

        request = region.RequestAddBlock(0x66);
        region.AddBlock(request, (offset, size) => new Block(offset, size));

        request = region.RequestAddBlock(0x100);
        region.AddBlock(request, (offset, size) => new Block(offset, size));

        region.Blocks.RemoveAt(0);

        request = region.RequestAddBlock(0x66);
        region.AddBlock(request, (offset, size) => new Block(offset, size));
    }
}