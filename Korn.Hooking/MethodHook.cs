using Korn.Utils.Logger;
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
        var methodParameters = MethodInfoUtils.GetParameters(method);
        var targetParameters = MethodInfoUtils.GetParameters(TargetMethod);

        string? message = null;

        if (!method.IsStatic)
        {
            message = "method must be static";
            goto Return;
        }

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
            throw new KornError([
                $"MethodHook->VerifySignature: Bad method signature - {message}.",
                $"Expected signature: {GenerateSignature()}"
            ]);

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
            Disable();

        Hooks.Add(hook);
        BuildStub();

        if (isHooked)
            Enable();
    }

    public void RemoveHook(MethodInfoSummary hook)
    {
        var isRemoved = Hooks.Remove(hook);

        if (isRemoved)
        {
            var isEnabled = IsHooked;
            if (isEnabled)
                Disable();

            BuildStub();

            if (isEnabled)
                Enable();
        }
    }

    public void Enable()
    {
        if (IsHooked)
            return;
        IsHooked = true;

        *TargetSnapshoot.Target = StubSnapshoot.TargetSnapshoot;
    }

    public void Disable()
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