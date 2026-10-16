using Fleetory.Platform.Contracts;

namespace Fleetory.Platform.Search;

internal sealed class SearchService : ISearchService
{
    private readonly ISearchProvider[] _providers;

    public SearchService(IEnumerable<ISearchProvider> providers)
    {
        ArgumentNullException.ThrowIfNull(providers);
        _providers = providers.ToArray();
    }

    public async ValueTask<IReadOnlyList<SearchResult>> SearchAsync(
        SearchRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (string.IsNullOrWhiteSpace(request.Query) || request.Limit <= 0 || _providers.Length == 0)
        {
            return Array.Empty<SearchResult>();
        }

        var results = new List<SearchResult>(request.Limit);

        foreach (var provider in _providers)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var providerResults = await provider.SearchAsync(request, cancellationToken).ConfigureAwait(false);

            foreach (var result in providerResults)
            {
                results.Add(result);
                if (results.Count == request.Limit)
                {
                    return results.ToArray();
                }
            }
        }

        return results.ToArray();
    }
}
