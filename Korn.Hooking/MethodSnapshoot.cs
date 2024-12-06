using Korn.CLR;
using System.Reflection;

namespace Korn.Hooking;
public unsafe struct MethodSnapshoot
{
    public MethodSnapshoot(MethodInfo methodInfo) : this(clr_MethodDesc.ExtractFrom(methodInfo)) { }
    public MethodSnapshoot(clr_MethodDesc* methodDesc)
    {
        if (methodDesc is null)
            throw new ArgumentNullException(
                $"[Korn.Hooking] MethodSnapshoot->.ctor(clr_MethodDesc*): " +
                 "The method descriptor is null"
            );

        var data = methodDesc->GetPrecode()->AsFixupPrecode()->GetData();
        Target = &data->Target;
        TargetSnapshoot = data->Target;
    }

    public void** Target;
    public void* TargetSnapshoot;
}