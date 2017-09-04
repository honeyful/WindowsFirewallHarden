using System;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using WindowsFirewallHelper;
namespace WindowaFirewallHarden
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
                consoleText();
                switch (readInt())
                {
                    case 0:
                        Environment.Exit(0);
                        break;

                    case 1:
                        hardenFirewall();
                        break;

                    case 2:
                        resetFirewall();
                        break;

                    default:
                        errText(1);
                        break;
                        
                }
            }
        }

        static int readInt()
        {
            Console.Write(">>>");
            return int.Parse(Console.ReadLine());
        }

        static void consoleText()
        {
            Console.WriteLine("++++++++++++++++++++");
            Console.WriteLine("0. Exit");
            Console.WriteLine("1. Harden");
            Console.WriteLine("2. Reset");
            Console.WriteLine("++++++++++++++++++++");
        }

        static void errText(int errNum)
        {
            switch(errNum)
            {
                case 1:
                    Console.WriteLine("[-] unknown command");
                    break;

                default:
                    Console.WriteLine("[-] unknown error");
                    break;
                    
            }
        }

        static void hardenFirewall()
        {
            resetFirewall();

            string[] rows = { programFiles, programFilesx86, winDir, appLocal, appRoaming };
            foreach (var dir in rows)
            {
                foreach (var file in GetFiles(dir, ext))
                {
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

            initRule();
        }
        
        static void resetFirewall()
        {
            try
            {
                var p = new Process();
                var pInfo = new ProcessStartInfo()
                {
                    FileName = "netsh.exe",
                    Arguments = "advfirewall reset",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardError = false,
                    RedirectStandardInput = false,
                    RedirectStandardOutput = false,
                };

                p.StartInfo = pInfo;
                p.Start();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                errText(2);
            }
         }

        static void initRule()
        {
            var domainMgr = FirewallManager.Instance.GetProfile(FirewallProfiles.Domain);
            var privateMgr = FirewallManager.Instance.GetProfile(FirewallProfiles.Private);
            var publicMgr = FirewallManager.Instance.GetProfile(FirewallProfiles.Public);

            domainMgr.DefaultInboundAction = FirewallAction.Block;
            domainMgr.DefaultOutboundAction = FirewallAction.Block;

            privateMgr.DefaultInboundAction = FirewallAction.Block;
            privateMgr.DefaultOutboundAction = FirewallAction.Block;

            publicMgr.DefaultInboundAction = FirewallAction.Block;
            publicMgr.DefaultOutboundAction = FirewallAction.Block;
        }
        static void allowRule(string fileName)
        {
            var rule = FirewallManager.Instance.CreateApplicationRule(
            FirewallManager.Instance.GetProfile().Type, fileName,
            FirewallAction.Allow,fileName);
            rule.Direction = FirewallDirection.Outbound;
            FirewallManager.Instance.Rules.Add(rule);
        }

        static void blockRule(string fileName)
        {
            var rule = FirewallManager.Instance.CreateApplicationRule(
            FirewallManager.Instance.GetProfile().Type, fileName,
            FirewallAction.Allow, fileName);
            rule.Direction = FirewallDirection.Outbound;
            FirewallManager.Instance.Rules.Add(rule);
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
