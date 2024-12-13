using System.Reflection;

namespace Korn.Hooking;
public static class MethodInfoUtils
{
    // Unlike the original MethodInfo.GetParameters this method adds to the parameters of this.
    // Not used extensions, as it may confuse developers.
    public static Type[] GetParameters(MethodInfo method)
    {
        var parameters = 
            method
            .GetParameters()
            .Select(param => param.ParameterType)
            .ToList();

        if (!method.IsStatic)
            parameters.Insert(0, method.DeclaringType!);

        return parameters.ToArray();
    }
}