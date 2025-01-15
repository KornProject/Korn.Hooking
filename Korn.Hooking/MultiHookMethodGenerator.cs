using System.Linq.Expressions;
using System.Reflection.Emit;
using System.Reflection;

namespace Korn.Hooking;
public unsafe static class MultiHookMethodGenerator
{
    static ModuleBuilder? definedModule;
    static ModuleBuilder ResolveDynamicAssembly()
    {
        if (definedModule is null)
            definedModule = DefineDynamicAssembly(Guid.NewGuid().ToString());

        return definedModule;
    }

    static ModuleBuilder DefineDynamicAssembly(string name)
    {
        var assemblyName = new AssemblyName(name);
        var assembly = AssemblyBuilder.DefineDynamicAssembly(assemblyName, AssemblyBuilderAccess.Run);
        var module = assembly.DefineDynamicModule(name);

        return module;
    }

    public static DynamicMethod Generate(MethodHook methodHook, MethodInfo target, List<MethodInfo> hooks)
    {
        var targetParameters = MethodInfoUtils.GetParameters(target);

        var moduleBuilder = ResolveDynamicAssembly();
        var typeBuilder = moduleBuilder.DefineType(
            Guid.NewGuid().ToString(),
            TypeAttributes.Public | TypeAttributes.AutoClass | TypeAttributes.AnsiClass | TypeAttributes.BeforeFieldInit
        );
        var fieldBuilder = typeBuilder.DefineField(
            Guid.NewGuid().ToString(),
            typeof(nint),
            FieldAttributes.Public | FieldAttributes.Static
        );
        var type = typeBuilder.CreateType();
        var stubTargetField = type.GetRuntimeFields().First()!;

        // DynamicMethod supports only public static methods
        var method = new DynamicMethod(
            name: Guid.NewGuid().ToString(),
            attributes: MethodAttributes.Public | MethodAttributes.Static,
            callingConvention: CallingConventions.Standard,
            returnType: target.ReturnType,
            parameterTypes: targetParameters,
            owner: type,
            skipVisibility: true
        );

        method.InitLocals = false;

        GenerateIL();

        Type delegateType;
        if (target.ReturnType == typeof(void))
            delegateType = Expression.GetActionType(targetParameters);
        else delegateType = Expression.GetFuncType([..targetParameters, target.ReturnType]);

        try
        {
            method.CreateDelegate(delegateType); // force the CLR to compile this method
        } 
        catch (Exception ex)
        {
            throw new KornExpectedException($"Incorrectly assembled hooking stub method for {target.Name}", ex);
        }

        var snapshoot = new MethodSnapshoot(method);
        stubTargetField.SetValue(null, (nint)snapshoot.TargetSnapshoot);

        return method;

        void GenerateIL()
        {
            var il = method.GetILGenerator();

            var targetLocal = il.DeclareLocal(typeof(void).MakePointerType().MakePointerType());
            var returnLabel = il.DefineLabel();

            var targetParameters = MethodInfoUtils.GetParameters(target);

            long targetPointerAddress = (nint)methodHook.TargetSnapshoot.Target;
            long targetAddress = (nint)methodHook.TargetSnapshoot.TargetSnapshoot;

            if (target.ReturnType == typeof(void))
            {
                /* prologue */
                il.Emit(OpCodes.Ldc_I8, targetPointerAddress);
                il.Emit(OpCodes.Conv_I);
                il.Emit(OpCodes.Stloc_0);
                il.Emit(OpCodes.Ldloc_0);
                il.Emit(OpCodes.Ldc_I8, targetAddress);
                il.Emit(OpCodes.Conv_I);
                il.Emit(OpCodes.Stind_I);

                /* hooks calling */
                foreach (var hook in hooks)
                {
                    for (var argIndex = 0; argIndex < targetParameters.Length; argIndex++)
                        il.Emit(OpCodes.Ldarga_S, (byte)argIndex);

                    il.Emit(OpCodes.Call, hook);
                    il.Emit(OpCodes.Brfalse, returnLabel);
                }

                /* target method calling */
                for (var argIndex = 0; argIndex < targetParameters.Length; argIndex++)
                {
                    if (targetParameters[argIndex].IsByRef)
                        il.Emit(OpCodes.Ldarga_S, (byte)argIndex);
                    else il.Emit(OpCodes.Ldarg_S, (byte)argIndex);
                }

                il.Emit(OpCodes.Call, target);

                il.MarkLabel(returnLabel);

                /* epilogue */
                il.Emit(OpCodes.Ldloc_0);
                il.Emit(OpCodes.Ldsfld, stubTargetField);
                il.Emit(OpCodes.Stind_I);
                il.Emit(OpCodes.Ret);
            }
            else
            {
                var resultLocal = il.DeclareLocal(target.ReturnType);

                /* prologue */
                il.Emit(OpCodes.Ldc_I8, targetPointerAddress);
                il.Emit(OpCodes.Conv_I);
                il.Emit(OpCodes.Stloc_0);
                il.Emit(OpCodes.Ldloc_0);
                il.Emit(OpCodes.Ldc_I8, targetAddress);
                il.Emit(OpCodes.Conv_I);
                il.Emit(OpCodes.Stind_I);

                /* hooks calling */
                foreach (var hook in hooks)
                {
                    for (var argIndex = 0; argIndex < targetParameters.Length; argIndex++)
                        il.Emit(OpCodes.Ldarga_S, (byte)argIndex);
                    il.Emit(OpCodes.Ldloca_S, 1);

                    il.Emit(OpCodes.Call, hook);
                    il.Emit(OpCodes.Brfalse, returnLabel);
                }

                /* target method calling */
                for (var argIndex = 0; argIndex < targetParameters.Length; argIndex++)
                {
                    if (targetParameters[argIndex].IsByRef)
                        il.Emit(OpCodes.Ldarga_S, (byte)argIndex);
                    else il.Emit(OpCodes.Ldarg_S, (byte)argIndex);
                }

                il.Emit(OpCodes.Call, target);
                il.Emit(OpCodes.Stloc_1);

                il.MarkLabel(returnLabel);

                /* epilogue */
                il.Emit(OpCodes.Ldloc_0);
                il.Emit(OpCodes.Ldsfld, stubTargetField);
                il.Emit(OpCodes.Stind_I);
                il.Emit(OpCodes.Ldloc_1);
                il.Emit(OpCodes.Ret);
            }
        }
    }
}