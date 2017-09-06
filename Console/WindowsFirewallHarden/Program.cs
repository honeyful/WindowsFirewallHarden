using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using NetFwTypeLib;

namespace WindowsFirewallHarden
{
    class Program
    {
        static string ext = "*.exe";
        static string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        static string programFilesx86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        static string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        static string appRoaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        static string appLocal = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        static void Main(string[] args)
        {
            while (true)
            {
                Console.WriteLine("++++++++++++++++++");
                Console.WriteLine("0. Exit");
                Console.WriteLine("1. Firewall Checker");
                Console.WriteLine("2. Firewall Harden");
                Console.WriteLine("3. Firewall Harden - No Init Rule");
                Console.WriteLine("4. Init Rule - Block All Inbound / Outbound Traffic ( Only Exception )");
                Console.WriteLine("5. Reset");
                Console.WriteLine("++++++++++++++++++");
                Console.Write(">>>");
                switch (int.Parse(Console.ReadLine()))
                {
                    case 0:
                        Environment.Exit(0);
                        break;

                    case 1:
                        fwChecker();
                        break;

                    case 2:
                        fwHarden(true);
                        break;

                    case 3:
                        fwHarden(false);
                        break;

                    case 4:
                        initRule();
                        break;

                    case 5:
                        fwReset();
                        break;

                    default:
                        break;
                }
            }
        }

        static void fwChecker()
        {

            domainFirewall();
            Console.WriteLine();

            privateFirewall();
            Console.WriteLine();

            publicFirewall();
            Console.WriteLine();
        }

        static void fwHarden(bool Init)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();

            Type tNetFwPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(tNetFwPolicy2);
            var currentProfiles = fwPolicy2.CurrentProfileTypes;
            List<string> ruleList = new List<string>();

            foreach (INetFwRule rule in fwPolicy2.Rules)
            {
                ruleList.Add(rule.Name.ToLower());
            }

            string[] rows = { programFiles, programFilesx86, winDir, appLocal, appRoaming };

            foreach (var dir in rows)
            {
                foreach (var file in GetFiles(dir, ext))
                {
                    var match = ruleList
                    .FirstOrDefault(stringToCheck => stringToCheck.Contains(file.ToLower()));

                    if (match != null) { Console.WriteLine($"[A]{file}"); continue; }
                    if (checkSignature(file))
                    {
                        Console.WriteLine($"[+] {file}");
                        allowRule(file);

                    }
                    else
                    {
                        Console.WriteLine($"[-] {file}");
                        blockRule(file);
                    }
                }
            }

            if (Init)
                initRule();

            sw.Stop();
            var elapsedMs = sw.ElapsedMilliseconds;
            Console.WriteLine($"Time:{elapsedMs}");
        }

        static void initRule()
        {
            Type netFwPolicy2Type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            INetFwPolicy2 mgr = (INetFwPolicy2)Activator.CreateInstance(netFwPolicy2Type);

            mgr.set_BlockAllInboundTraffic(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN, true);
            mgr.set_DefaultInboundAction(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN, NET_FW_ACTION_.NET_FW_ACTION_BLOCK);
            mgr.set_DefaultOutboundAction(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN, NET_FW_ACTION_.NET_FW_ACTION_BLOCK);

            mgr.set_BlockAllInboundTraffic(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE, true);
            mgr.set_DefaultInboundAction(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE, NET_FW_ACTION_.NET_FW_ACTION_BLOCK);
            mgr.set_DefaultOutboundAction(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE, NET_FW_ACTION_.NET_FW_ACTION_BLOCK);

            mgr.set_BlockAllInboundTraffic(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC, true);
            mgr.set_DefaultInboundAction(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC, NET_FW_ACTION_.NET_FW_ACTION_BLOCK);
            mgr.set_DefaultOutboundAction(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC, NET_FW_ACTION_.NET_FW_ACTION_BLOCK);

            Console.WriteLine("[+] Init Rule");
        }

        static void allowRule(string fileName)
        {
            INetFwRule fwRule = (INetFwRule)Activator.CreateInstance(
                 Type.GetTypeFromProgID("HNetCfg.FWRule"));
            fwRule.Action = NET_FW_ACTION_.NET_FW_ACTION_ALLOW;
            fwRule.Enabled = true;
            fwRule.InterfaceTypes = "All";
            fwRule.Name = fileName;
            fwRule.ApplicationName = fileName;
            INetFwPolicy2 fwPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            fwRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT;
            fwPolicy.Rules.Add(fwRule);
        }

        static void blockRule(string fileName)
        {
            INetFwRule fwRule = (INetFwRule)Activator.CreateInstance(
                Type.GetTypeFromProgID("HNetCfg.FWRule"));
            fwRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
            fwRule.Enabled = true;
            fwRule.InterfaceTypes = "All";
            fwRule.Name = fileName;
            fwRule.ApplicationName = fileName;
            INetFwPolicy2 fwPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            fwRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT;
            fwPolicy.Rules.Add(fwRule);
        }

        static void duplicateRule(string fileName)
        {
            INetFwPolicy2 fwPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            
        }

        static void fwReset()
        {
            Type netFwPolicy2Type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            INetFwPolicy2 mgr = (INetFwPolicy2)Activator.CreateInstance(netFwPolicy2Type);
            mgr.RestoreLocalFirewallDefaults();
            Console.WriteLine("Reset");
            Console.WriteLine();
        }

        static void domainFirewall()
        {
            Type netFwPolicy2Type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            INetFwPolicy2 mgr = (INetFwPolicy2)Activator.CreateInstance(netFwPolicy2Type);
            NET_FW_PROFILE_TYPE2_ fwDomainProfileType = NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN;

            Console.WriteLine("Domain Profile Type:");



            var firewallEnabled = mgr.get_FirewallEnabled(fwDomainProfileType);
            var blockAllInboundTraffic = mgr.get_BlockAllInboundTraffic(fwDomainProfileType);
            var defaultInboundAction = mgr.get_DefaultInboundAction(fwDomainProfileType);
            var defaultOutboundAction = mgr.get_DefaultOutboundAction(fwDomainProfileType);

            Console.WriteLine($"Firewall Enabled: {firewallEnabled.ToString()}");
            Console.WriteLine($"Block All Inbound Traffic: {blockAllInboundTraffic.ToString()}");
            Console.WriteLine($"Default Inbound Action:{defaultInboundAction.ToString()}");
            Console.WriteLine($"Default Outbound Action:{defaultOutboundAction.ToString()}");
        }

        static void privateFirewall()
        {
            Type netFwPolicy2Type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            INetFwPolicy2 mgr = (INetFwPolicy2)Activator.CreateInstance(netFwPolicy2Type);
            NET_FW_PROFILE_TYPE2_ fwPrivateProfileType = NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE;

            var firewallEnabled = mgr.get_FirewallEnabled(fwPrivateProfileType);
            var blockAllInboundTraffic = mgr.get_BlockAllInboundTraffic(fwPrivateProfileType);
            var defaultInboundAction = mgr.get_DefaultInboundAction(fwPrivateProfileType);
            var defaultOutboundAction = mgr.get_DefaultOutboundAction(fwPrivateProfileType);

            Console.WriteLine($"Firewall Enabled: {firewallEnabled.ToString()}");
            Console.WriteLine($"Block All Inbound Traffic: {blockAllInboundTraffic.ToString()}");
            Console.WriteLine($"Default Inbound Action:{defaultInboundAction.ToString()}");
            Console.WriteLine($"Default Outbound Action:{defaultOutboundAction.ToString()}");
        }

        static void publicFirewall()
        {
            Type netFwPolicy2Type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            INetFwPolicy2 mgr = (INetFwPolicy2)Activator.CreateInstance(netFwPolicy2Type);
            NET_FW_PROFILE_TYPE2_ fwPublicProfileType = NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC;

            var firewallEnabled = mgr.get_FirewallEnabled(fwPublicProfileType);
            var blockAllInboundTraffic = mgr.get_BlockAllInboundTraffic(fwPublicProfileType);
            var defaultInboundAction = mgr.get_DefaultInboundAction(fwPublicProfileType);
            var defaultOutboundAction = mgr.get_DefaultOutboundAction(fwPublicProfileType);

            Console.WriteLine($"Firewall Enabled: {firewallEnabled.ToString()}");
            Console.WriteLine($"Block All Inbound Traffic: {blockAllInboundTraffic.ToString()}");
            Console.WriteLine($"Default Inbound Action:{defaultInboundAction.ToString()}");
            Console.WriteLine($"Default Outbound Action:{defaultOutboundAction.ToString()}");
        }

        static bool checkSignature(string fileName)
        {
            var certChain = new X509Chain();
            var cert = default(X509Certificate2);
            bool isChainValid = false;
            try
            {
                var signer = X509Certificate.CreateFromSignedFile(fileName);
                cert = new X509Certificate2(signer);
            }
            catch
            {
                return isChainValid;
            }

            certChain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            certChain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            certChain.ChainPolicy.UrlRetrieval‎Timeout = new TimeSpan(0, 1, 0);
            certChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            isChainValid = certChain.Build(cert);

            return isChainValid;

        }

        static IEnumerable<string> GetFiles(string path, string exts)
        {
            Queue<string> q = new Queue<string>();
            q.Enqueue(path);
            while (q.Count > 0)
            {
                path = q.Dequeue();
                try
                {
                    foreach (string subDir in Directory.GetDirectories(path))
                    {
                        q.Enqueue(subDir);
                    }
                }
                catch
                {

                }
                string[] files = null;
                try
                {
                    files = Directory.GetFiles(path, exts);
                }
                catch
                {

                }
                if (files != null)
                {
                    for (int i = 0; i < files.Length; i++)
                    {
                        yield return files[i];
                    }
                }
            }
        }
    }
}
