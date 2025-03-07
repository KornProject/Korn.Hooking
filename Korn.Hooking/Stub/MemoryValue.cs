abstract class MemoryValue { }

class StackValue : MemoryValue
{
    public StackValue(int offset) => Offset = offset;
    public int Offset;
}

class RegisterValue : MemoryValue
{
    public RegisterValue(ArgumentRegister register) => Register = register;
    public ArgumentRegister Register;
}