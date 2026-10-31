using Fleetory.CommandSigner.Host;

await using var app = SigningHostApplication.Build(args);
await app.RunAsync();
