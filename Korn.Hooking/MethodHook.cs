using System.Collections.Generic;
using System.Reflection;
using System.Linq;
using System;
using Korn.Utils.Algorithms;

namespace Korn.Hooking
{
    public unsafe class MethodHook
    {
        static List<MethodHook> ActiveHooks = new List<MethodHook>();

        MethodHook(MethodInfoSummary targetMethod)
        {
            this.targetMethod = targetMethod;

            stub = new MethodStub(targetMethod);
            ActiveHooks.Add(this);
        }

        public MethodStub DEBUG_Stub => stub;

        MethodStub stub;
        MethodInfo targetMethod;
        
        List<HookEntry> entries = new List<HookEntry>();

        public bool IsEnabled { get; private set; }

        void VerifySignature(MethodInfo method)
        {
            var methodParameters = method.GetArgumentsEx();
            var targetParameters = targetMethod.GetArgumentsEx();

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

        public MethodHook AddEntry(Delegate hookDelegate) => AddEntry(hookDelegate.Method);
        public MethodHook AddEntry(MethodInfoSummary method) => AddEntry(method.Method);
        public MethodHook AddEntry(MethodInfo method)
        {
            VerifySignature(method);

            var methodStatement = MethodStatement.From(method);

            var memoryNode = stub.AddHook(methodStatement.NativeCodePointer);
            var entry = new HookEntry(this, methodStatement, memoryNode);
            return AddEntry(entry);
        }
        MethodHook AddEntry(HookEntry entry)
        {
            entries.Add(entry);

            if (entries.Count == 1 && IsEnabled)
                stub.EnableRedirection();

            return this;
        }

        public MethodHook RemoveEntry(Delegate hookDelegate) => RemoveEntry(hookDelegate.Method);
        public MethodHook RemoveEntry(MethodInfoSummary method) => RemoveEntry(method.Method);
        public MethodHook RemoveEntry(MethodInfo method)
        {
            foreach (var entry in entries)
                if (entry.MethodStatement.Method == method)
                    return RemoveEntry(entry);

            return this;
        }
        MethodHook RemoveEntry(HookEntry entry)
        {
            if (entries.Count == 1)
                stub.DisableRedirection();

            stub.RemoveHook(entry.LinkedNode);
            entries.Remove(entry);
            return this;
        }

        public MethodHook Enable()
        {
            if (!IsEnabled)
            {
                IsEnabled = true;
                stub.EnableRedirection();
            }            

            return this;
        }

        public MethodHook Disable()
        {
            if (IsEnabled)
            {
                IsEnabled = false;
                stub.DisableRedirection();
            }

            return this;
        }

        public MethodHook RemoveAllEntries()
        {
            while (entries.Count != 0)
                RemoveEntry(entries[0].MethodStatement.Method);
            return this;
        }

        public override string ToString() 
            => $"{{ Method: {targetMethod.Name}, DelegatePointer: {targetMethod.MethodHandle.GetFunctionPointer().ToHexString()}, Enabled: {IsEnabled}, Stub: {stub} }}";            

        public static MethodHook Create(Delegate targetMethodDelegate) => Create(targetMethodDelegate.Method);
        public static MethodHook Create(MethodInfoSummary targetMethodSumarry) => Create(targetMethodSumarry.Method);
        public static MethodHook Create(MethodInfo targetMethod)
        {
            foreach (var hook in ActiveHooks)
                if (hook.targetMethod == targetMethod)
                    return hook;

            return new MethodHook(targetMethod);
        }

        public class HookEntry
        {
            public HookEntry(MethodHook owner, MethodStatement methodStatement, LinkedNode* memoryNode)
            {
                HookOwner = owner;
                MethodStatement = methodStatement;
                LinkedNode = memoryNode;
            }

            public readonly MethodHook HookOwner;
            public readonly MethodStatement MethodStatement;
            public readonly LinkedNode* LinkedNode;
        }
    }
}