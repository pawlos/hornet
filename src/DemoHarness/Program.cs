using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using DotNetFuzzing.Shared;
using SharpFuzz;

HarnessHelpers.AddExpectedExceptionPatterns("JsonException");

// Out-of-process fuzzing: AFL++ forks the process, sends mutated input via stdin.
// SharpFuzz handles the fork server protocol and coverage feedback.
Fuzzer.OutOfProcess.Run(stream =>
{
    HarnessHelpers.RunWithExceptionFilter(() =>
    {
        using var reader = new StreamReader(stream);
        var text = reader.ReadToEnd();

        // Parse with Newtonsoft.Json and exercise various code paths
        using var jsonReader = new JsonTextReader(new StringReader(text));
        jsonReader.DateParseHandling = DateParseHandling.None;

        var token = JToken.ReadFrom(jsonReader);

        // Walk the parsed tree to exercise deeper code paths
        WalkToken(token);
    });
});

static void WalkToken(JToken token)
{
    switch (token)
    {
        case JObject obj:
            foreach (var prop in obj.Properties())
            {
                _ = prop.Name;
                WalkToken(prop.Value);
            }
            break;
        case JArray arr:
            foreach (var item in arr)
            {
                WalkToken(item);
            }
            break;
        case JValue val:
            _ = val.ToString();
            break;
    }
}
