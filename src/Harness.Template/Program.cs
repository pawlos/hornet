using DotNetFuzzing.Shared;
using SharpFuzz;

// Out-of-process fuzzing: AFL++ forks the process, sends mutated input via stdin.
// SharpFuzz handles the fork server protocol and coverage feedback.
Fuzzer.OutOfProcess.Run(stream =>
{
    HarnessHelpers.RunWithExceptionFilter(() =>
    {
        // Option A: Binary input — use the stream directly.
        // Good for image parsers, binary formats, etc.
        //
        //     var bytes = new byte[stream.Length];
        //     stream.ReadExactly(bytes);
        //     MyLibrary.Parse(bytes);

        // Option B: Text input — read as string first.
        // Good for JSON, XML, YAML, CSV, etc.
        //
        //     using var reader = new StreamReader(stream);
        //     var text = reader.ReadToEnd();
        //     MyLibrary.Parse(text);

        // TODO: Replace with your target library's parsing/processing logic.
        // Tips:
        //   - Exercise as many code paths as possible (parse, validate, serialize, round-trip)
        //   - Keep the harness simple — avoid file I/O, network, or heavy allocations
        //   - If the library has multiple entry points, call them all
        //   - Create stateful objects (parsers, settings) OUTSIDE the Run() callback
        //     if they are expensive to construct and can be reused

        throw new NotImplementedException("Replace this with your fuzzing target");
    });
});
