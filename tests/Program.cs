using System.Text.Json.Nodes;
using WinDiagnostics;
var failures=0;var passed=0;
void Assert(bool value,string why){if(!value)throw new Exception(why);}
void Reject(Action action){try{action();}catch(ArgumentException){return;}throw new Exception("expected ArgumentException");}
void Has(List<Finding> f,string id)=>Assert(f.Any(x=>x.Id==id),"missing finding "+id);
void Check(string name,Action body){try{body();passed++;Console.WriteLine("PASS "+name);}catch(Exception e){failures++;Console.Error.WriteLine("FAIL "+name+": "+e);}}
async Task AsyncCheck(string name,Func<Task> body){try{await body();passed++;Console.WriteLine("PASS "+name);}catch(Exception e){failures++;Console.Error.WriteLine("FAIL "+name+": "+e);}}
var fixturePath=Path.Combine(AppContext.BaseDirectory,"fixture.json");
JsonObject Snapshot()=>(JsonObject)JsonNode.Parse(File.ReadAllText(fixturePath))!;
JsonObject Fixture()=>(JsonObject)Snapshot()["evidence"]!.DeepClone();
Check("fixture schema and snapshot replay",()=>{var c=Core.ReadSnapshot(Snapshot());Tool.ValidateEvidence(c.Evidence);Assert(c.Issues.Count==0,"fixture issues");Assert(Tool.Analyze(c.Evidence).Count>0,"fixture finding");});
Check("strict arguments and snapshot ownership",()=>{Reject(()=>Options.Parse(["--unknown"],Tool.ValueOptions,Tool.Flags));Reject(()=>Options.Parse(["--input"],Tool.ValueOptions,Tool.Flags));Reject(()=>Options.Parse(["--json","--json"],Tool.ValueOptions,Tool.Flags));var s=Snapshot();s["tool"]="another-tool";Reject(()=>Core.ReadSnapshot(s));s=Snapshot();s["schemaVersion"]=2;Reject(()=>Core.ReadSnapshot(s));s=Snapshot();s["issues"]=null;Reject(()=>Core.ReadSnapshot(s));Reject(()=>Tool.ValidateEvidence(new JsonObject()));});
Check("hosts and answer differences are contextual clues",()=>{var f=Tool.Analyze(Fixture());Has(f,"hosts-override");Has(f,"dns-answer-difference");Assert(f.First(x=>x.Id=="dns-answer-difference").Severity=="info","DNS difference must not claim a definite fault");});
Check("address set equality ignores order and IPv6 spelling",()=>{Assert(Tool.SameAddresses(["192.0.2.1","2001:0db8::1"],["2001:db8::1","192.0.2.1","192.0.2.1"]),"address equivalence");Reject(()=>Tool.ValidateOptions(Options.Parse(["--host","bad name"],Tool.ValueOptions,Tool.Flags)));Reject(()=>Tool.ValidateOptions(Options.Parse(["--host","192.0.2.1"],Tool.ValueOptions,Tool.Flags)));});
if(OperatingSystem.IsWindows()&&Tool.SmokeArgs.Length>0)await AsyncCheck("Windows live collector smoke",async()=>{using var ct=new CancellationTokenSource(TimeSpan.FromSeconds(100));var o=Options.Parse(Tool.SmokeArgs,Tool.ValueOptions,Tool.Flags);Tool.ValidateOptions(o);var c=await Tool.Collect(o,ct.Token);Tool.ValidateEvidence(c.Evidence);Console.WriteLine($"Live collector issues: {c.Issues.Count}");});
Console.WriteLine($"{passed} passed; {failures} failed");
return failures==0?0:1;
