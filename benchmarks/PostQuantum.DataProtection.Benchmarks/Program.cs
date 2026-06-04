using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Running;

var config = DefaultConfig.Instance
    .AddDiagnoser(MemoryDiagnoser.Default);

BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args, config);
