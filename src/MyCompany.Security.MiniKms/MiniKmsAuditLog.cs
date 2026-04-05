using MyCompany.Security.MiniKms.Client;

namespace MyCompany.Security.MiniKms;

internal interface IMiniKmsAuditLog
{
    void Write(string action, string outcome, string actor, string? keyVersion, string details);

    IReadOnlyList<MiniKmsAuditEntry> List(int take);
}

internal sealed class InMemoryMiniKmsAuditLog : IMiniKmsAuditLog
{
    private const int MaxEntries = 500;

    private readonly object _sync = new();
    private readonly LinkedList<MiniKmsAuditEntry> _entries = new();

    public void Write(string action, string outcome, string actor, string? keyVersion, string details)
    {
        var entry = new MiniKmsAuditEntry(
            Guid.NewGuid().ToString("N"),
            DateTimeOffset.UtcNow,
            action,
            outcome,
            string.IsNullOrWhiteSpace(actor) ? "system" : actor.Trim(),
            string.IsNullOrWhiteSpace(keyVersion) ? null : keyVersion.Trim(),
            details);

        lock (_sync)
        {
            _entries.AddFirst(entry);
            while (_entries.Count > MaxEntries)
            {
                _entries.RemoveLast();
            }
        }
    }

    public IReadOnlyList<MiniKmsAuditEntry> List(int take)
    {
        var boundedTake = take <= 0 ? 50 : Math.Min(take, 200);
        lock (_sync)
        {
            return _entries.Take(boundedTake).ToArray();
        }
    }
}
