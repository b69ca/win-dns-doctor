using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
namespace WinDiagnostics;
public static class Tool
{
    public const string Name="win-dns-doctor";
    public static readonly string[] ValueOptions=["--host"];
    public static readonly string[] Flags=["--system-only"];
    public const string Help="win-dns-doctor --host example.com [--system-only] [--json]\nCompares system resolution with A/AAAA queries to up to 8 configured DNS servers. --system-only skips direct queries.";
    public static void ValidateOptions(Options o){J.Host(o.Get("--host"));if(IPAddress.TryParse(o.Get("--host"),out _))throw new ArgumentException("--host must be a DNS name, not an IP address.");}
    public static Task<Collection> Collect(Options o,CancellationToken ct)=>PowerShell.Collect(new(){["WD_TARGET"]=o.Get("--host"),["WD_SYSTEM_ONLY"]=o.Has("--system-only")?"1":"0"},ct);
    public static void ValidateEvidence(JsonObject e){J.Require(e,"host","system","adapters","queries","hostsEntries","directQueriesSkipped");if(e["system"] is not JsonObject)throw new ArgumentException("Evidence system must be an object.");foreach(var key in new[]{"adapters","queries","hostsEntries"})J.RequireRows(e,key);}
    public static bool SameAddresses(IEnumerable<string> a,IEnumerable<string> b)=>a.Select(Canonical).ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(b.Select(Canonical));
    private static string Canonical(string a)=>IPAddress.TryParse(a,out var ip)?ip.ToString():a;
    public static List<Finding> Analyze(JsonObject e)
    {
        var r=new List<Finding>();var system=e["system"]!;
        if(!J.Bool(system,"success"))r.Add(new("system-resolution-failed","error","The Windows system resolver failed",J.Text(system,"error","No addresses were returned."),"Check hosts entries, DNS configuration, DNS client policy, and the direct-query results."));
        if(J.Rows(e,"hostsEntries").Any())r.Add(new("hosts-override","info","A matching hosts-file entry exists","System resolution may use the hosts file; direct DNS queries intentionally bypass it.","Confirm the entry is intentional before changing it."));
        var queries=J.Rows(e,"queries").ToArray();
        if(!J.Bool(e,"directQueriesSkipped")&&queries.Length>0&&queries.All(q=>!J.Bool(q,"success")))r.Add(new("direct-queries-failed","warning","All recorded direct DNS queries failed","Failures can include NXDOMAIN, missing record families, network failures, or policy restrictions; consult each query's error.","Test the configured servers and verify the requested name exists."));
        foreach(var q in queries.Where(q=>J.Bool(q,"success")))
        {
            var family=J.Text(q,"type")=="AAAA"?AddressFamily.InterNetworkV6:AddressFamily.InterNetwork;
            var expected=J.Strings(system,"addresses").Where(a=>IPAddress.TryParse(a,out var ip)&&ip.AddressFamily==family);
            if(J.Bool(system,"success")&&!SameAddresses(expected,J.Strings(q,"addresses")))r.Add(new("dns-answer-difference","info","A direct DNS answer differs from system resolution",$"Server {J.Text(q,"server")} ({J.Text(q,"type")}) returned a different address set. Caching, load balancing, hosts entries, VPNs, and resolver policy can all cause this.","Compare records, TTLs, network context, and intended split-DNS behavior; a difference alone is not a fault."));
        }
        if(J.Bool(e,"serversCapped"))r.Add(new("dns-server-cap","warning","Only eight DNS servers were queried","Additional configured servers were omitted.","Use the adapter inventory to query any omitted server separately."));return r;
    }
    public static IEnumerable<string> Describe(JsonObject e){yield return $"Name: {J.Text(e,"host")}";yield return $"System resolver: {string.Join(", ",J.Strings(e["system"],"addresses"))} {J.Text(e["system"],"error")}";foreach(var a in J.Rows(e,"adapters"))yield return $"Adapter {J.Text(a,"name")}: {string.Join(", ",J.Strings(a,"servers"))}";foreach(var h in J.Rows(e,"hostsEntries"))yield return $"Hosts entry: {J.Text(h,"address")} {J.Text(h,"name")}";foreach(var q in J.Rows(e,"queries"))yield return $"{J.Text(q,"server")} {J.Text(q,"type")}: {string.Join(", ",J.Strings(q,"addresses"))} {J.Text(q,"error")}";}
    public static string[] SmokeArgs=>["--host","localhost","--system-only"];
}
