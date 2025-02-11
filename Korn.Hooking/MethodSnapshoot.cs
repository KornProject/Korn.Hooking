using Korn.CoreCLR;
using System.Reflection;

namespace Korn.Hooking;
public unsafe struct MethodSnapshoot
{
    public MethodSnapshoot(MethodInfo methodInfo) : this(clr_MethodDesc.ExtractFrom(methodInfo)) { }
    public MethodSnapshoot(clr_MethodDesc* methodDesc)
    {
        if (methodDesc is null)
            throw new KornError([
                "MethodSnapshoot->.ctor(clr_MethodDesc*):",
                "The method descriptor is null."
            ]);

        var precode = methodDesc->GetPrecode();
        var type = precode->GetType();

        if (!precode->IsFixupPrecode())
            if (methodDesc is null)
                throw new KornError([
                    "MethodSnapshoot->.ctor(clr_MethodDesc*):",
                    "The method precode is not Fixup.",
                    "Other precodes is not implemented."
                ]);

        var fixupPrecode = precode->AsFixupPrecode();        
        var data = fixupPrecode->GetData();

        Target = &data->Target;
        TargetSnapshoot = data->Target;
    }

    public void** Target;
    public void* TargetSnapshoot;
}