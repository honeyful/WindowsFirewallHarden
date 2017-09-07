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
        private volatile bool _stop = false;

        OpenFileDialog ofd;
        SaveFileDialog sfd;
        FolderBrowserDialog fbd;

        public MainFrame()
        {
            InitializeComponent();
        }

        private void MainFrame_Load(object sender, EventArgs e)
        {
            FormBorderStyle = FormBorderStyle.FixedToolWindow;
            lvLog.Columns.Add("Path", 300);
            lvLog.Columns.Add("Status", 100);
            lvExclude.Columns.Add("Path", 300);
            lvExclude.Columns.Add("Type", 100);
        }

        #region Firewall
        private void fwHarden()
        {
            if (_stop) return;
            CheckForIllegalCrossThreadCalls = false;
            var sw = System.Diagnostics.Stopwatch.StartNew();

            btnReset.Enabled = false;
            btnSave.Enabled = false;
            btnDir.Enabled = false;
            btnFile.Enabled = false;
            btnRemove.Enabled = false;

            Type tNetFwPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(tNetFwPolicy2);
            var currentProfiles = fwPolicy2.CurrentProfileTypes;
            List<string> ruleList = new List<string>();

            foreach (INetFwRule rule in fwPolicy2.Rules)
            {
                if (_stop) return;
                ruleList.Add(rule.Name.ToLower());
            }

            string[] rows = { programFiles, programFilesx86, winDir, appLocal, appRoaming };

            foreach (var dir in rows)
            {
                if (_stop) return;
                foreach (var file in GetFiles(dir, ext))
                {
                    if (_stop) return;
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

            btnReset.Enabled = true;
            btnSave.Enabled = true;
            btnDir.Enabled = true;
            btnFile.Enabled = true;
            btnRemove.Enabled = true;
            btnHarden.Text = "Harden";

            sw.Stop();
            var elapsedMs = sw.ElapsedMilliseconds;
            MessageBox.Show("Done" + Environment.NewLine + $"Time:{elapsedMs}");
        }
        
        private void excludeRule()
        {
            CheckForIllegalCrossThreadCalls = false;

            if (lvExclude.Items.Count > 0)
            {
                foreach (var item in lvExclude.Items.Cast<ListViewItem>())
                {
                    if (_stop) return;
                    if (item.SubItems[1].Name == "File")
                    {
                        string[] rows = { item.Text, "Exclude" };
                        ListViewItem lvi = new ListViewItem(rows);
                        addItemToListView(lvLog, lvi);
                        allowRule(lvi.Name);
                    }
                    else
                    {
                        foreach (var file in GetFiles(item.Text, ext))
                        {
                            if (_stop) return;
                            string[] rows = { file, "Exclude" };
                            ListViewItem lvi = new ListViewItem(rows);
                            addItemToListView(lvLog, lvi);
                            allowRule(file);
                        }
                    }
                }
            }

            new Thread(fwHarden).Start();

        }      

        private void initRule()
        {
            Type netFwPolicy2Type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            INetFwPolicy2 mgr = (INetFwPolicy2)Activator.CreateInstance(netFwPolicy2Type);

            mgr.set_BlockAllInboundTraffic(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN, radBlockInbound.Checked ? true : false);
            mgr.set_DefaultInboundAction(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN, NET_FW_ACTION_.NET_FW_ACTION_BLOCK);
            mgr.set_DefaultOutboundAction(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN, !radBlockOutbound.Checked ? NET_FW_ACTION_.NET_FW_ACTION_ALLOW : NET_FW_ACTION_.NET_FW_ACTION_BLOCK);

            mgr.set_BlockAllInboundTraffic(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE, radBlockInbound.Checked ? true : false);
            mgr.set_DefaultInboundAction(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE, NET_FW_ACTION_.NET_FW_ACTION_BLOCK);
            mgr.set_DefaultOutboundAction(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE, NET_FW_ACTION_.NET_FW_ACTION_BLOCK);

            mgr.set_BlockAllInboundTraffic(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC, radBlockInbound.Checked ? true : false);
            mgr.set_DefaultInboundAction(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC, NET_FW_ACTION_.NET_FW_ACTION_BLOCK);
            mgr.set_DefaultOutboundAction(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC, !radBlockOutbound.Checked ? NET_FW_ACTION_.NET_FW_ACTION_ALLOW : NET_FW_ACTION_.NET_FW_ACTION_BLOCK);
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

        private delegate void removeToListViewDelegate(ListView lv, ListViewItem lvi);
        private void removeItemToListView(ListView lv, ListViewItem lvi)
        {
            if (lv.InvokeRequired)
            {
                Invoke(new removeToListViewDelegate(removeItemToListView), new object[] { lv, lvi });
                return;
            }
            lv.Items.Remove(lvi);
        }

        private void exportListView(ListView lv, string split)
        {
            using (sfd = new SaveFileDialog())
            {
                sfd.Filter = "Text Files (.txt | *.txt)";
                
                if(sfd.ShowDialog() == DialogResult.OK)
                {
                    if(sfd.FileName != null)
                    {
                        using (StreamWriter sw = new StreamWriter(sfd.FileName))
                        {
                            foreach (ListViewItem item in lv.Items)
                            {
                                sw.WriteLine("{0}{1}{2}", item.SubItems[0].Text, split, item.SubItems[1].Text);
                            }
                        }
                    }
                }
            }
        }
        #endregion

        private void btnHarden_Click(object sender, EventArgs e)
        {
            if(btnHarden.Text == "Harden")
            {
                _stop = false;
                lvLog.Items.Clear();
                new Thread(excludeRule).Start();
                btnHarden.Text = "Stop";
            }
            else
            {
                _stop = true;
                btnHarden.Text = "Harden";
                btnReset.Enabled = true;
                btnSave.Enabled = true;
                btnDir.Enabled = true;
                btnFile.Enabled = true;
                btnRemove.Enabled = true;
            }
        }

        private void btnReset_Click(object sender, EventArgs e)
        {
            fwReset();
            MessageBox.Show("Reset");
        }

        private void btnSave_Click(object sender, EventArgs e)
        {
            exportListView(lvLog, "|");
        }

        private void btnDir_Click(object sender, EventArgs e)
        {
            using (fbd = new FolderBrowserDialog())
            {
                if (fbd.ShowDialog() == DialogResult.OK)
                {
                    string[] rows = { fbd.SelectedPath, "Directory" };
                    ListViewItem lvi = new ListViewItem(rows);
                    addItemToListView(lvExclude, lvi);
                }
            }
        }

        private void btnFile_Click(object sender, EventArgs e)
        {
            using (ofd = new OpenFileDialog())
            {
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    string[] rows = { ofd.FileName, "File" };
                    ListViewItem lvi = new ListViewItem(rows);
                    addItemToListView(lvExclude, lvi);
                }
            }
        }

        private void btnRemove_Click(object sender, EventArgs e)
        {
            removeItemToListView(lvExclude, lvExclude.SelectedItems[0]);
        }
    }
}
