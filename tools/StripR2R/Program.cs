// Strips ReadyToRun (R2R) native code from .NET assemblies
// by reading with Mono.Cecil and re-writing as pure IL.
using Mono.Cecil;

if (args.Length == 0)
{
    Console.Error.WriteLine("Usage: StripR2R <assembly.dll> [assembly2.dll ...]");
    return 1;
}

foreach (var path in args)
{
    if (!File.Exists(path))
    {
        Console.Error.WriteLine($"File not found: {path}");
        return 1;
    }

    var tmp = path + ".tmp";
    var resolver = new DefaultAssemblyResolver();
    resolver.AddSearchDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
    using (var assembly = AssemblyDefinition.ReadAssembly(path,
        new ReaderParameters { ReadWrite = false, AssemblyResolver = resolver }))
    {
        assembly.Write(tmp);
    }

    File.Move(tmp, path, overwrite: true);
    Console.WriteLine($"Stripped R2R: {Path.GetFileName(path)}");
}

return 0;
