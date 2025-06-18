using System.Collections.Generic;
using Korn.Modules.Algorithms;
using System.Reflection;
using System.Linq;
using System;

namespace Korn.Hooking
{
    public unsafe class MethodHook
    {
        static List<MethodHook> activeHooks = new List<MethodHook>();

        MethodHook(MethodInfoSummary targetMethod)
        {
            this.targetMethod = targetMethod;

            stub = new MethodStub(targetMethod);
            activeHooks.Add(this);
        }

        public MethodStub DEBUG_Stub => stub;

        MethodStub stub;
        MethodInfo targetMethod;        
        List<HookEntry> entries = new List<HookEntry>();

        public bool IsEnabled { get; private set; }

        void VerifySignature(MethodInfo method)
        {
            var methodArguments = method.GetArgumentsEx();
            var targetArguments = targetMethod.GetArgumentsEx();
            var targetParameters = targetMethod.GetParametersEx();

            if (!method.IsStatic)
                Throw("method must be static");
            
            if (method.ReturnType != typeof(bool))
                Throw("return type must be 'bool'");

            if (methodArguments.Length != targetParameters.Length)
                Throw("wrong number of arguments");

            if (methodArguments.Any(param => !param.IsByRef))
                Throw("all arguments must have the ref modifier");

            for (var argIndex = 0; argIndex < targetParameters.Length; argIndex++)
                if (targetParameters[argIndex].FullName.Contains(methodArguments[argIndex].FullName))
                    Throw(
                        $"the type of {argIndex + 1}-th, {methodArguments[argIndex].Name}, " +
                        $"argument is not the same as expected {targetParameters[argIndex].Name}"
                    );
            
            void Throw(string message)
            {
                throw new KornError(
                    $"MethodHook->VerifySignature: Bad method signature: \"{message}\".",
                    $"Expected signature: {GenerateExpectedSignature()}"
                );
            }

            string GenerateExpectedSignature() => $"bool {method.Name}({string.Join(" ", targetArguments.Select(t => $"ref {t.Name}"))})";
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
            foreach (var hook in activeHooks)
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