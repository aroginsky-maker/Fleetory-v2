using Fleetory.Assets.Contracts;
using Fleetory.CMDB.Contracts;
using Fleetory.Core.Contracts;
using Fleetory.Integrations.Contracts;
using Fleetory.ITSM.Contracts;
using Fleetory.Monitoring.Contracts;
using Fleetory.Platform.Contracts;
using Fleetory.SharedKernel;

namespace Fleetory.Architecture.Tests;

public sealed class ContractFoundationTests
{
    [Fact]
    public void Semantic_identifiers_preserve_values_without_collapsing_domain_types()
    {
        var value = Guid.NewGuid();

        Assert.Equal(value, new PersonId(value).Value);
        Assert.Equal(value, new ScopeId(value).Value);
        Assert.Equal(value, new DeviceId(value).Value);
        Assert.Equal(value, new AssetId(value).Value);
        Assert.Equal(value, new TicketId(value).Value);
        Assert.Equal(value, new ConfigurationItemId(value).Value);
        Assert.Equal(value, new ObservationId(value).Value);
        Assert.Equal(value, new EventId(value).Value);
        Assert.Equal(value, new AlertId(value).Value);
        Assert.Equal(value, new ConnectorId(value).Value);

        Assert.NotEqual(typeof(DeviceId), typeof(AssetId));
        Assert.NotEqual(typeof(DeviceId), typeof(ConfigurationItemId));
    }

    [Fact]
    public void Summary_contracts_preserve_only_their_public_identity_and_label()
    {
        var person = new PersonSummary(new PersonId(Guid.NewGuid()), "Ada Lovelace");
        var scope = new ScopeSummary(new ScopeId(Guid.NewGuid()), "EMEA");
        var device = new DeviceSummary(new DeviceId(Guid.NewGuid()), "NB-00421");
        var asset = new AssetSummary(new AssetId(Guid.NewGuid()), "Laptop 421");
        var ticket = new TicketSummary(new TicketId(Guid.NewGuid()), "VPN access request");
        var configurationItem = new ConfigurationItemSummary(new ConfigurationItemId(Guid.NewGuid()), "Payroll API");
        var alert = new AlertSummary(new AlertId(Guid.NewGuid()), "High CPU");

        Assert.Equal("Ada Lovelace", person.DisplayName);
        Assert.Equal("EMEA", scope.Name);
        Assert.Equal("NB-00421", device.DisplayName);
        Assert.Equal("Laptop 421", asset.DisplayName);
        Assert.Equal("VPN access request", ticket.Title);
        Assert.Equal("Payroll API", configurationItem.Name);
        Assert.Equal("High CPU", alert.Title);
    }

    [Fact]
    public void Event_envelope_carries_transport_neutral_metadata()
    {
        var envelopeId = Guid.NewGuid();
        var causationId = Guid.NewGuid();
        var occurredAt = new DateTimeOffset(2026, 9, 27, 12, 0, 0, TimeSpan.Zero);
        var correlationId = new CorrelationId("phase3-correlation");
        var subject = new EventSubject("Core.Device", Guid.NewGuid().ToString("D"));
        var envelope = new EventEnvelope
        {
            EventId = envelopeId,
            EventType = "Core.DeviceStateChanged",
            SchemaVersion = 1,
            OccurredAt = occurredAt,
            CorrelationId = correlationId,
            CausationId = causationId,
            Producer = "Fleetory.Core",
            Subject = subject
        };

        Assert.Equal(envelopeId, envelope.EventId);
        Assert.Equal("Core.DeviceStateChanged", envelope.EventType);
        Assert.Equal(1, envelope.SchemaVersion);
        Assert.Equal(occurredAt, envelope.OccurredAt);
        Assert.Equal(correlationId, envelope.CorrelationId);
        Assert.Equal<Guid?>(causationId, envelope.CausationId);
        Assert.Equal("Fleetory.Core", envelope.Producer);
        Assert.Equal(subject, envelope.Subject);
    }

    [Fact]
    public void Data_provenance_preserves_source_timing_and_authority_metadata()
    {
        var observedAt = new DateTimeOffset(2026, 9, 27, 11, 59, 0, TimeSpan.Zero);
        var receivedAt = new DateTimeOffset(2026, 9, 27, 12, 0, 0, TimeSpan.Zero);
        var provenance = new DataProvenance(
            "Fleetory.Agent",
            "device-421",
            observedAt,
            receivedAt,
            "PreferredLiveTechnicalSource");

        Assert.Equal("Fleetory.Agent", provenance.SourceSystem);
        Assert.Equal("device-421", provenance.SourceRecordId);
        Assert.Equal(observedAt, provenance.ObservedAt);
        Assert.Equal<DateTimeOffset?>(receivedAt, provenance.ReceivedAt);
        Assert.Equal("PreferredLiveTechnicalSource", provenance.Authority);
    }
}
