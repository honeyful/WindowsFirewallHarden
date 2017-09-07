using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows.Forms;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using NetFwTypeLib;

namespace WindowsFirewallHarden
{
    public partial class MainFrame : Form
    {
        private const string ext = "*.exe";
        private readonly string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        private readonly string programFilesx86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        private readonly string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        private readonly string appRoaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        private readonly string appLocal = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        public MainFrame()
        {
            InitializeComponent();
        }

        private void MainFrame_Load(object sender, EventArgs e)
        {
            lvLog.Columns.Add("Path", 300);
            lvLog.Columns.Add("Status", 100);
            lvExclude.Columns.Add("Path", 300);
            lvExclude.Columns.Add("Type", 100);
        }

        #region Firewall
        private void fwHarden()
        {
            //var sw = System.Diagnostics.Stopwatch.StartNew();

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

                    if (match != null)
                    {
                        string[] items = { file, "Already" };
                        ListViewItem lvi = new ListViewItem(items);
                        addItemToListView(lvLog, lvi);

                        continue;
                    }
                    if (checkSignature(file))
                    {
                        string[] items = { file, "Allow" };
                        ListViewItem lvi = new ListViewItem(items);
                        addItemToListView(lvLog, lvi);

                        allowRule(file);
                    }
                    else
                    {
                        string[] items = { file, "Block" };
                        ListViewItem lvi = new ListViewItem(items);
                        addItemToListView(lvLog, lvi);

                        blockRule(file);
                    }
                }
            }
            
                initRule();

            //sw.Stop();
            //var elapsedMs = sw.ElapsedMilliseconds;
            //Console.WriteLine($"Time:{elapsedMs}");
        }

        private void initRule()
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
        }

        private void allowRule(string fileName)
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

        private void blockRule(string fileName)
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

        private void fwReset()
        {
            Type netFwPolicy2Type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            INetFwPolicy2 mgr = (INetFwPolicy2)Activator.CreateInstance(netFwPolicy2Type);
            mgr.RestoreLocalFirewallDefaults();
        }

        private bool checkSignature(string fileName)
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

        private IEnumerable<string> GetFiles(string path, string exts)
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

        #endregion

        #region ListView
        private delegate void addToListViewDelegate(ListView lv, ListViewItem lvi);
        private void addItemToListView(ListView lv, ListViewItem lvi)
        {
            if (lv.InvokeRequired)
            {
                Invoke(new addToListViewDelegate(addItemToListView), new object[] { lv, lvi });
                return;
            }
            lv.Items.Add(lvi);
        }
        #endregion

        private void btnHarden_Click(object sender, EventArgs e)
        {
            new Thread(fwHarden).Start();
        }

        private void btnReset_Click(object sender, EventArgs e)
        {
            fwReset();
        }

        private void btnSave_Click(object sender, EventArgs e)
        {

        }
    }
}
