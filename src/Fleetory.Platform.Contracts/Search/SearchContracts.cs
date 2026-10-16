namespace Fleetory.Platform.Contracts;

public sealed record SearchRequest(
    string Query,
    int Limit = 20);

public sealed record SearchResult(
    string SourceModule,
    string ResultType,
    string ResultId,
    string DisplayName);

public interface ISearchProvider
{
    string SourceModule { get; }

    ValueTask<IReadOnlyList<SearchResult>> SearchAsync(
        SearchRequest request,
        CancellationToken cancellationToken = default);
}

public interface ISearchService
{
    ValueTask<IReadOnlyList<SearchResult>> SearchAsync(
        SearchRequest request,
        CancellationToken cancellationToken = default);
}
