using System.Reflection;
using System.Runtime.CompilerServices;

namespace Korn.Hooking;
public unsafe class MethodHook
{
    static List<MethodHook> ActiveHooks = [];

    MethodHook(MethodInfoSummary targetMethod)
    {
        TargetMethod = targetMethod;

        RuntimeHelpers.PrepareMethod(TargetMethod.MethodHandle);
        TargetSnapshoot = new(targetMethod);
    }

    public readonly MethodSnapshoot TargetSnapshoot;
    public readonly MethodInfo TargetMethod;

    public MethodSnapshoot StubSnapshoot { get; private set; }
    public MethodInfo? StubMethod { get; private set; }

    public readonly List<MethodInfo> Hooks = [];
    public bool IsHooked { get; private set; }

    void VerifySignature(MethodInfo method)
    {
        var methodParameters = method.GetParameters().Select(param => param.ParameterType).ToList();
        var targetParameters = TargetMethod.GetParameters().Select(param => param.ParameterType).ToList();

        string? message = null;

        if (method.ReturnType != typeof(bool))
        {
            message = "return type must be 'bool'";
            goto Return;
        }

        var exprectedArgumentTypes = targetParameters.ToList();
        if (TargetMethod.ReturnType != typeof(void))
            exprectedArgumentTypes.Add(TargetMethod.ReturnType);

        if (method.GetParameters().Length != exprectedArgumentTypes.Count)
        {
            message = "wrong number of arguments";
            goto Return;
        }

        var foundNonRefArgument = methodParameters.FirstOrDefault(param => !param.IsByRef);
        if (foundNonRefArgument is not null)
        {
            message = "all arguments must have the ref modifier";
            goto Return;
        }

        for (var argIndex = 0; argIndex < exprectedArgumentTypes.Count; argIndex++)
            if (exprectedArgumentTypes[argIndex].FullName!.Contains(methodParameters[argIndex].FullName!))
            // you are laughing, but I really don't know how to do type checking with RefBy ignored
            {
                message = $"the type of {argIndex + 1}-th, {methodParameters[argIndex].Name}, " +
                          $"argument is not the same as expected {exprectedArgumentTypes[argIndex].Name}";
                goto Return;
            }

        Return:
        if (message is not null)
            throw new Exception(
                $"[Korn.Hooking] MethodHook->VerifySignature: Bad method signature - " + message + ".\n" +
                $"Expected signature: {GenerateSignature()}"
            );

        return;

        string GenerateSignature()
        {
            var types = TargetMethod.GetParameters().Select(param => param.ParameterType).ToList();
            if (TargetMethod.ReturnType != typeof(void))
                types.Add(TargetMethod.ReturnType);

            return $"bool HookImplementation({string.Join(' ', types.Select(t => $"ref {t.Name}"))})";
        }

    }

    public void AddHook(MethodInfoSummary hook)
    {
        VerifySignature(hook);

        var isHooked = IsHooked;
        if (isHooked)
            Unhook();

        Hooks.Add(hook);
        BuildStub();

        if (isHooked)
            Hook();
    }

    public void RemoveHook(MethodInfoSummary hook)
    {
        var isRemoved = Hooks.Remove(hook);

        if (isRemoved)
        {
            var isHooked = IsHooked;
            if (isHooked)
                Unhook();

            BuildStub();

            if (isHooked)
                Hook();
        }
    }

    public void Hook()
    {
        if (IsHooked)
            return;
        IsHooked = true;

        *TargetSnapshoot.Target = StubSnapshoot.TargetSnapshoot;
    }

    public void Unhook()
    {
        if (!IsHooked)
            return;
        IsHooked = false;

        *TargetSnapshoot.Target = TargetSnapshoot.TargetSnapshoot;
    }

    void BuildStub()
    {
        StubMethod = MultiHookMethodGenerator.Generate(this, TargetMethod, Hooks);
        StubSnapshoot = new(StubMethod);
    }

    public static MethodHook Create(MethodInfoSummary targetMethod)
    {
        var existsHook = ActiveHooks.FirstOrDefault(hook => hook.TargetMethod == targetMethod.Method);
        if (existsHook is not null)
            return existsHook;
        return new(targetMethod);
    }
}