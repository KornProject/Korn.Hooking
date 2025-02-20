using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using static Korn.Hooking.MethodAllocator;

namespace Korn.Hooking
{
    public unsafe class MethodHook
    {
        static List<MethodHook> ActiveHooks = new List<MethodHook>();

        MethodHook(MethodInfoSummary targetMethod)
        {
            this.targetMethod = targetMethod;

            stub = new Stub(this);
            ActiveHooks.Add(this);
        }

        Stub stub;
        MethodInfo targetMethod;
        
        List<HookEntry> hooks = new List<HookEntry>();

        public bool IsEnabled { get; private set; }

        void VerifySignature(MethodInfo method)
        {
            var methodParameters = MethodInfoUtils.GetParameters(method);
            var targetParameters = MethodInfoUtils.GetParameters(targetMethod);

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
            if (targetMethod.ReturnType != typeof(void))
                exprectedArgumentTypes.Add(targetMethod.ReturnType);

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
                var types = targetMethod.GetParameters().Select(param => param.ParameterType).ToList();
                if (targetMethod.ReturnType != typeof(void))
                    types.Add(targetMethod.ReturnType);

                return $"bool HookImplementation({string.Join(" ", types.Select(t => $"ref {t.Name}"))})";
            }
        }

        public MethodHook AddHook(Delegate hookDelegate) => AddHook(hookDelegate.Method);

        public MethodHook AddHook(MethodInfoSummary method)
        {
            VerifySignature(method);

            var methodStatement = new MethodStatement(method.Method);
            methodStatement.EnsureMethodIsCompiled();

            //var hook = new HookEntry(this, methodStatement, );
            //return AddHook(hook);
            return null;
        }

        public MethodHook AddHook(HookEntry hook)
        {
            hooks.Add(hook);
            //BuildStub();

            return this;
        }

        public MethodHook RemoveHook(Delegate hookDelegate) => RemoveHook(hookDelegate.Method);
        public MethodHook RemoveHook(MethodInfoSummary method)
        {
            //var isRemoved = hooks.Remove(method);

            //if (isRemoved)
            //{
            //    BuildStub();
            //}

            return this;
        }

        public MethodHook RemoveHook(HookEntry hook)
        {
            //var isRemoved = hooks.Remove(method);

            //if (isRemoved)
            //{
            //    BuildStub();
            //}

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

        public static MethodHook Create(Delegate targetMethodDelegate) => Create(targetMethodDelegate.Method);
        public static MethodHook Create(MethodInfoSummary targetMethod)
        {
            var existsHook = ActiveHooks.FirstOrDefault(hook => hook.targetMethod == targetMethod.Method);
            if (existsHook != null)
                return existsHook;
            return new MethodHook(targetMethod);
        }

        public class Stub
        {
            public Stub(MethodHook owner)
            {
                Owner = owner;

                targetStatement = new MethodStatement(owner.targetMethod);
                targetStatement.EnsureMethodIsCompiled();

                hooksArray = MethodAllocator.Instance.CreateLinkedArray();
            }

            public MethodHook Owner { get; private set; }

            MethodStatement targetStatement;
            LinkedArray hooksArray;
            List<Indirect> indirects;
            Indirect stubIndirect;
            Routine stubRoutine;
        }

        public class HookEntry
        {
            public HookEntry(
                MethodHook owner, 
                MethodStatement methodStatement, 
                LinkedArray.Node* memoryNode)
            {
                HookOwner = owner;
                MethodStatement = methodStatement;
                MemoryNode = memoryNode;
            }

            public MethodHook HookOwner { get; private set; }
            public MethodStatement MethodStatement { get; private set; }
            public LinkedArray.Node* MemoryNode { get; private set; }
        }
    }
}