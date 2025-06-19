using Korn;
using Korn.Hooking;
using Korn.Logger;
using System.Collections.Generic;

class JitWatcherMethodPool
{
    List<MethodStatement> methodPool = new List<MethodStatement>();

    public int Count => methodPool.Count;

    public MethodStatement this[int index] => methodPool[index];

    public void Add(MethodStatement method)
    {
        if (method == null)
            throw new KornError("Trying to add null-method to method statements pool for watcher.");

        lock (methodPool)
            methodPool.Add(method);
    }

    public void Remove(MethodStatement method)
    {
        lock (methodPool)
            methodPool.Remove(method);
    }
}