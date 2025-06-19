using static Stack;
using System.Collections.Generic;

class MethodStack
{
    public MethodStack(Stack stack)
    {
        var method = stack.Method;
        var arguments = method.GetArgumentsEx().Length;
        for (var argumentIndex = 0; argumentIndex < arguments; argumentIndex++)
        {
            var argument = new MethodArgument(stack, argumentIndex);
            Arguments.Add(argument);
            Parameters.Add(argument);
        }

        if (method.ReturnType != typeof(void))
        {
            HasReturnType = true;

            var parameterIndex = arguments;
            ReturnType = new MethodArgument(stack, parameterIndex);
            Parameters.Add(ReturnType);
        }
    }

    public readonly List<MethodArgument> Arguments = new List<MethodArgument>();
    public readonly List<MethodArgument> Parameters = new List<MethodArgument>();

    public readonly bool HasReturnType;
    public readonly MethodArgument ReturnType;
}