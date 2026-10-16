using System.Collections.ObjectModel;
using Fleetory.ModuleAbstractions;
using Fleetory.Platform.Contracts;

namespace Fleetory.Platform.Modules;

internal sealed class ModuleRegistry : IModuleRegistry
{
    private readonly ReadOnlyCollection<ModuleRegistration> _modules;
    private readonly Dictionary<string, ModuleRegistration> _modulesById;

    public ModuleRegistry(IReadOnlyCollection<IFleetoryModule> modules)
    {
        ArgumentNullException.ThrowIfNull(modules);

        var duplicateName = modules
            .GroupBy(module => module.Name, StringComparer.Ordinal)
            .FirstOrDefault(group => group.Count() > 1);

        if (duplicateName is not null)
        {
            throw new InvalidOperationException(
                $"Duplicate Fleetory module name: {duplicateName.Key}.");
        }

        var registrations = modules
            .Select(module => new ModuleRegistration(
                module.Name,
                module.Name,
                IsRegistered: true))
            .OrderBy(module => module.ModuleId, StringComparer.Ordinal)
            .ToArray();

        _modules = Array.AsReadOnly(registrations);
        _modulesById = registrations.ToDictionary(
            module => module.ModuleId,
            StringComparer.Ordinal);
    }

    public IReadOnlyList<ModuleRegistration> GetModules() => _modules;

    public ModuleRegistration? Find(string moduleId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(moduleId);
        return _modulesById.GetValueOrDefault(moduleId);
    }
}
