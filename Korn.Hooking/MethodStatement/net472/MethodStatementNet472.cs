using System.Reflection;
using System.Threading;
using Korn.Utils;

namespace Korn.Hooking
{
    unsafe class MethodStatementNet472 : MethodStatement
    {
        public MethodStatementNet472(MethodInfo method) : base(method) { }

        private protected override void EnsureMethodIsCompiled()
        {
            if (IsCompiled)
                return;

            var pointer = DelegatePointer;
            var dasm = (Disassembler*)&pointer;

            while (true)
            {
                if (dasm->IsCallRel32Instruction)
                {
                    Thread.Sleep(1);
                    continue;
                }

                if (dasm->IsJmpRel32Instruction)
                    pointer = dasm->GetJmpRel32Operand();

                NativeCodePointer = pointer;
                IsCompiled = true;
                return;
            }
        }
    }
}