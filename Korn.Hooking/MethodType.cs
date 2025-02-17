namespace Korn.Hooking
{
    public enum MethodType
    {
        None,
        NotCompiledStub,
        ThresholdCounterStub,
        DirectNativeStub,
        UnknownStub,
        Native
    }

    public static class MethodTypeExtensions
    {
        public static bool IsNative(this MethodType self) => self == MethodType.Native || self == MethodType.DirectNativeStub;
    }
}