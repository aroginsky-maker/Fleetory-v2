namespace Fleetory.Platform.Contracts;

public sealed record ModuleRegistration(
    string ModuleId,
    string DisplayName,
    bool IsRegistered);

public interface IModuleRegistry
{
    IReadOnlyList<ModuleRegistration> GetModules();

    ModuleRegistration? Find(string moduleId);
}
