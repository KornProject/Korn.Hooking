using Korn.Hooking;
using System;

static class Extensions
{
    public static MethodHook AddEntryEx(this MethodHook self, Type type, string name)
    {
        var method = type.GetMethodEx(name);
        return self.AddEntry(method);
    }
}