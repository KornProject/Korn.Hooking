using static Stack;
using System;

class MethodArgument
{
    public MethodArgument(Stack stack, int index)
    {
        if (index <= 3)
        {
            var register = (ArgumentRegister)Enum.GetValues(typeof(ArgumentRegister)).GetValue(index);
            InputValue = new RegisterValue(register);
            CallingValue = new RegisterValue(register);
        }
        else
        {
            InputValue = new StackValue(stack.GetOffsetForPrevStack(index - 4));
            CallingValue = new StackValue(stack.GetOffsetForStartStack(index - 4));
        }

        StoreValue = new StackValue(stack.GetOffsetForEndStack(index * 2));
        PointerToStoreValue = new StackValue(stack.GetOffsetForEndStack(index * 2 + 1));
    }

    public MemoryValue InputValue, StoreValue, PointerToStoreValue, CallingValue;
}