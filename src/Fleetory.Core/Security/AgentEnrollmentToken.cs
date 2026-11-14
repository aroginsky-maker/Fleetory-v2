using System.Security.Cryptography;
using System.Text;

namespace Fleetory.Core.Security;

internal static class AgentEnrollmentToken
{
    public static string Create() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    public static string Hash(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(token)));
}
