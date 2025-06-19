using System.Reflection;

class Stack
{
    const int ClrRoutineStackOffset = 0x20;

    public Stack(MethodInfo method)
    {
        Method = method;

        HasReturnType = method.ReturnType != typeof(void);
        ArgumentsCount = method.GetArgumentsEx().Length;
        ParamsCount = ArgumentsCount + (HasReturnType ? 1 : 0);
    }

    public readonly MethodInfo Method;
    public readonly bool HasReturnType;
    public readonly int ArgumentsCount;
    public readonly int ParamsCount;

    public int InitialPrevStackOffset { get; private set; }

    int lastCalculatedMaxStack = -1;
    public int MaxStack => lastCalculatedMaxStack == -1 ? (lastCalculatedMaxStack = CalculateMaxStack()) : lastCalculatedMaxStack;

    public void SetInitialPrevStackStartOffset(int offset) => InitialPrevStackOffset = offset;

    int CalculateMaxStack()
    {
        var value = (ParamsCount * 2 * 0x08) + (ParamsCount > 4 ? ((ParamsCount - 4) * 2 * 0x08) : 0) + ClrRoutineStackOffset;
        if ((value + InitialPrevStackOffset) % 0x10 == 0)
            value += 0x08;
        return value;
    }

    public int GetOffsetForPrevStack(int index) => InitialPrevStackOffset + ClrRoutineStackOffset + MaxStack + index * 0x08 + 0x08/*call return address*/;
    public int GetOffsetForStartStack(int index) => ClrRoutineStackOffset + index * 0x08;
    public int GetOffsetForEndStack(int index) => MaxStack - index * 0x08 - 0x08;

    public MethodStack BuildMethodStack() => new MethodStack(this);
}