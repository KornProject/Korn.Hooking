using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace Korn.Hooking
{
    public unsafe class MethodHook
    {
        static List<MethodHook> ActiveHooks = new List<MethodHook>();

        MethodHook(MethodInfoSummary targetMethod)
        {
            TargetMethod = targetMethod;

            TargetStatement = new MethodStatement(targetMethod);
            TargetStatement.EnsureMethodIsCompiled();

            ActiveHooks.Add(this);
        }

        public readonly MethodStatement TargetStatement;
        public readonly MethodInfo TargetMethod;

        public MethodStatement StubStatement { get; private set; }
        public MethodInfo StubMethod { get; private set; }

        public readonly List<MethodInfo> Hooks = new List<MethodInfo>();
        public bool IsEnabled { get; private set; }

        void VerifySignature(MethodInfo method)
        {
            var methodParameters = MethodInfoUtils.GetParameters(method);
            var targetParameters = MethodInfoUtils.GetParameters(TargetMethod);

            string message = null;

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
            if (foundNonRefArgument != null)
            {
                message = "all arguments must have the ref modifier";
                goto Return;
            }

            for (var argIndex = 0; argIndex < exprectedArgumentTypes.Count; argIndex++)
                if (exprectedArgumentTypes[argIndex].FullName.Contains(methodParameters[argIndex].FullName))
                // you are laughing, but I really don't know how to do type checking with RefBy ignored
                {
                    message = $"the type of {argIndex + 1}-th, {methodParameters[argIndex].Name}, " +
                              $"argument is not the same as expected {exprectedArgumentTypes[argIndex].Name}";
                    goto Return;
                }

            Return:
            if (message != null)
                throw new KornError(
                    $"MethodHook->VerifySignature: Bad method signature - {message}.",
                    $"Expected signature: {GenerateSignature()}"
                );

            return;

            string GenerateSignature()
            {
                var types = TargetMethod.GetParameters().Select(param => param.ParameterType).ToList();
                if (TargetMethod.ReturnType != typeof(void))
                    types.Add(TargetMethod.ReturnType);

                return $"bool HookImplementation({string.Join(" ", types.Select(t => $"ref {t.Name}"))})";
            }
        }

        public MethodHook AddHook(Delegate hookDelegate) => AddHook(hookDelegate.Method);
        public MethodHook AddHook(MethodInfoSummary hook)
        {
            VerifySignature(hook);

            var isEnabled = IsEnabled;
            if (isEnabled)
                Disable();

            Hooks.Add(hook);
            BuildStub();

            if (isEnabled)
                Enable();

            return this;
        }

        public MethodHook RemoveHook(Delegate hookDelegate) => RemoveHook(hookDelegate.Method);
        public MethodHook RemoveHook(MethodInfoSummary hook)
        {
            var isRemoved = Hooks.Remove(hook);

            if (isRemoved)
            {
                var isEnabled = IsEnabled;
                if (isEnabled)
                    Disable();

                BuildStub();

                if (isEnabled)
                    Enable();
            }

            return this;
        }

        public void Enable()
        {
            if (IsEnabled)
                return;
            IsEnabled = true;

            //*TargetStatement.Target = StubSnapshoot.TargetSnapshoot;
        }

        public void Disable()
        {
            if (!IsEnabled)
                return;
            IsEnabled = false;

            //*TargetStatement.Target = TargetStatement.TargetSnapshoot;
        }

        void BuildStub()
        {
            //StubMethod = MultiHookMethodGenerator.Generate(this, TargetMethod, Hooks);
            StubStatement = new MethodStatement(StubMethod);
        }

        public static MethodHook Create(Delegate targetMethodDelegate) => Create(targetMethodDelegate.Method);
        public static MethodHook Create(MethodInfoSummary targetMethod)
        {
            var existsHook = ActiveHooks.FirstOrDefault(hook => hook.TargetMethod == targetMethod.Method);
            if (existsHook != null)
                return existsHook;
            return new MethodHook(targetMethod);
        }
    }
}