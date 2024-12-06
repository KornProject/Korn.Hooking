using System.Reflection;

namespace Korn.Hooking;
public record struct MethodInfoSummary(MethodInfo Method)
{
    public static implicit operator MethodInfo(MethodInfoSummary self) => self.Method;
    public static implicit operator MethodInfoSummary(MethodInfo method) => new(method);
    public static implicit operator MethodInfoSummary(Delegate method) => new(method.Method);
}