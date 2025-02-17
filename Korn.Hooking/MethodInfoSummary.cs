using System;
using System.Reflection;

namespace Korn.Hooking
{
    public struct MethodInfoSummary
    {
        public MethodInfoSummary(MethodInfo method) => Method = method;

        public readonly MethodInfo Method;

        public static implicit operator MethodInfo(MethodInfoSummary self) => self.Method;
        public static implicit operator MethodInfoSummary(MethodInfo method) => new MethodInfoSummary(method);
        public static implicit operator MethodInfoSummary(Delegate method) => new MethodInfoSummary(method.Method);
    }
}