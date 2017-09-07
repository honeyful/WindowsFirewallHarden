namespace WindowsFirewallHarden
{
    partial class MainFrame
    {
        /// <summary>
        /// 필수 디자이너 변수입니다.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// 사용 중인 모든 리소스를 정리합니다.
        /// </summary>
        /// <param name="disposing">관리되는 리소스를 삭제해야 하면 true이고, 그렇지 않으면 false입니다.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form 디자이너에서 생성한 코드

        /// <summary>
        /// 디자이너 지원에 필요한 메서드입니다. 
        /// 이 메서드의 내용을 코드 편집기로 수정하지 마세요.
        /// </summary>
        private void InitializeComponent()
        {
            this.btnSave = new System.Windows.Forms.Button();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.radBlockInbound = new System.Windows.Forms.RadioButton();
            this.radAllowInbound = new System.Windows.Forms.RadioButton();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.radBlockOutbound = new System.Windows.Forms.RadioButton();
            this.radAllowOutbound = new System.Windows.Forms.RadioButton();
            this.lvLog = new WindowsFirewallHarden.AeroListView();
            this.btnReset = new System.Windows.Forms.Button();
            this.btnHarden = new System.Windows.Forms.Button();
            this.groupBox3 = new System.Windows.Forms.GroupBox();
            this.btnRemove = new System.Windows.Forms.Button();
            this.btnFile = new System.Windows.Forms.Button();
            this.btnDir = new System.Windows.Forms.Button();
            this.lvExclude = new WindowsFirewallHarden.AeroListView();
            this.groupBox4 = new System.Windows.Forms.GroupBox();
            this.progressBar = new System.Windows.Forms.ProgressBar();
            this.groupBox1.SuspendLayout();
            this.groupBox2.SuspendLayout();
            this.groupBox3.SuspendLayout();
            this.groupBox4.SuspendLayout();
            this.SuspendLayout();
            // 
            // btnSave
            // 
            this.btnSave.Location = new System.Drawing.Point(308, 205);
            this.btnSave.Name = "btnSave";
            this.btnSave.Size = new System.Drawing.Size(93, 23);
            this.btnSave.TabIndex = 0;
            this.btnSave.Text = "SaveLog";
            this.btnSave.UseVisualStyleBackColor = true;
            this.btnSave.Click += new System.EventHandler(this.btnSave_Click);
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.radBlockInbound);
            this.groupBox1.Controls.Add(this.radAllowInbound);
            this.groupBox1.Location = new System.Drawing.Point(12, 12);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(200, 70);
            this.groupBox1.TabIndex = 1;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Inbound";
            // 
            // radBlockInbound
            // 
            this.radBlockInbound.AutoSize = true;
            this.radBlockInbound.Checked = true;
            this.radBlockInbound.Location = new System.Drawing.Point(6, 42);
            this.radBlockInbound.Name = "radBlockInbound";
            this.radBlockInbound.Size = new System.Drawing.Size(54, 16);
            this.radBlockInbound.TabIndex = 1;
            this.radBlockInbound.TabStop = true;
            this.radBlockInbound.Text = "Block";
            this.radBlockInbound.UseVisualStyleBackColor = true;
            // 
            // radAllowInbound
            // 
            this.radAllowInbound.AutoSize = true;
            this.radAllowInbound.Location = new System.Drawing.Point(6, 20);
            this.radAllowInbound.Name = "radAllowInbound";
            this.radAllowInbound.Size = new System.Drawing.Size(54, 16);
            this.radAllowInbound.TabIndex = 0;
            this.radAllowInbound.Text = "Allow";
            this.radAllowInbound.UseVisualStyleBackColor = true;
            // 
            // groupBox2
            // 
            this.groupBox2.Controls.Add(this.radBlockOutbound);
            this.groupBox2.Controls.Add(this.radAllowOutbound);
            this.groupBox2.Location = new System.Drawing.Point(221, 12);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(200, 70);
            this.groupBox2.TabIndex = 2;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "Outbound";
            // 
            // radBlockOutbound
            // 
            this.radBlockOutbound.AutoSize = true;
            this.radBlockOutbound.Checked = true;
            this.radBlockOutbound.Location = new System.Drawing.Point(6, 42);
            this.radBlockOutbound.Name = "radBlockOutbound";
            this.radBlockOutbound.Size = new System.Drawing.Size(54, 16);
            this.radBlockOutbound.TabIndex = 3;
            this.radBlockOutbound.TabStop = true;
            this.radBlockOutbound.Text = "Block";
            this.radBlockOutbound.UseVisualStyleBackColor = true;
            // 
            // radAllowOutbound
            // 
            this.radAllowOutbound.AutoSize = true;
            this.radAllowOutbound.Location = new System.Drawing.Point(6, 20);
            this.radAllowOutbound.Name = "radAllowOutbound";
            this.radAllowOutbound.Size = new System.Drawing.Size(54, 16);
            this.radAllowOutbound.TabIndex = 2;
            this.radAllowOutbound.Text = "Allow";
            this.radAllowOutbound.UseVisualStyleBackColor = true;
            // 
            // lvLog
            // 
            this.lvLog.FullRowSelect = true;
            this.lvLog.Location = new System.Drawing.Point(6, 20);
            this.lvLog.Name = "lvLog";
            this.lvLog.Size = new System.Drawing.Size(395, 179);
            this.lvLog.TabIndex = 3;
            this.lvLog.UseCompatibleStateImageBehavior = false;
            this.lvLog.View = System.Windows.Forms.View.Details;
            // 
            // btnReset
            // 
            this.btnReset.Location = new System.Drawing.Point(172, 205);
            this.btnReset.Name = "btnReset";
            this.btnReset.Size = new System.Drawing.Size(130, 23);
            this.btnReset.TabIndex = 4;
            this.btnReset.Text = "Reset";
            this.btnReset.UseVisualStyleBackColor = true;
            this.btnReset.Click += new System.EventHandler(this.btnReset_Click);
            // 
            // btnHarden
            // 
            this.btnHarden.Location = new System.Drawing.Point(6, 205);
            this.btnHarden.Name = "btnHarden";
            this.btnHarden.Size = new System.Drawing.Size(160, 23);
            this.btnHarden.TabIndex = 5;
            this.btnHarden.Text = "Harden";
            this.btnHarden.UseVisualStyleBackColor = true;
            this.btnHarden.Click += new System.EventHandler(this.btnHarden_Click);
            // 
            // groupBox3
            // 
            this.groupBox3.Controls.Add(this.btnRemove);
            this.groupBox3.Controls.Add(this.btnFile);
            this.groupBox3.Controls.Add(this.btnDir);
            this.groupBox3.Controls.Add(this.lvExclude);
            this.groupBox3.Location = new System.Drawing.Point(427, 12);
            this.groupBox3.Name = "groupBox3";
            this.groupBox3.Size = new System.Drawing.Size(409, 317);
            this.groupBox3.TabIndex = 7;
            this.groupBox3.TabStop = false;
            this.groupBox3.Text = "Exclude";
            // 
            // btnRemove
            // 
            this.btnRemove.Location = new System.Drawing.Point(314, 281);
            this.btnRemove.Name = "btnRemove";
            this.btnRemove.Size = new System.Drawing.Size(89, 23);
            this.btnRemove.TabIndex = 8;
            this.btnRemove.Text = "Remove";
            this.btnRemove.UseVisualStyleBackColor = true;
            this.btnRemove.Click += new System.EventHandler(this.btnRemove_Click);
            // 
            // btnFile
            // 
            this.btnFile.Location = new System.Drawing.Point(172, 281);
            this.btnFile.Name = "btnFile";
            this.btnFile.Size = new System.Drawing.Size(136, 23);
            this.btnFile.TabIndex = 7;
            this.btnFile.Text = "Add File";
            this.btnFile.UseVisualStyleBackColor = true;
            this.btnFile.Click += new System.EventHandler(this.btnFile_Click);
            // 
            // btnDir
            // 
            this.btnDir.Location = new System.Drawing.Point(6, 281);
            this.btnDir.Name = "btnDir";
            this.btnDir.Size = new System.Drawing.Size(160, 23);
            this.btnDir.TabIndex = 6;
            this.btnDir.Text = "Add Directory";
            this.btnDir.UseVisualStyleBackColor = true;
            this.btnDir.Click += new System.EventHandler(this.btnDir_Click);
            // 
            // lvExclude
            // 
            this.lvExclude.FullRowSelect = true;
            this.lvExclude.Location = new System.Drawing.Point(6, 15);
            this.lvExclude.Name = "lvExclude";
            this.lvExclude.Size = new System.Drawing.Size(397, 260);
            this.lvExclude.TabIndex = 4;
            this.lvExclude.UseCompatibleStateImageBehavior = false;
            this.lvExclude.View = System.Windows.Forms.View.Details;
            // 
            // groupBox4
            // 
            this.groupBox4.Controls.Add(this.lvLog);
            this.groupBox4.Controls.Add(this.btnSave);
            this.groupBox4.Controls.Add(this.btnHarden);
            this.groupBox4.Controls.Add(this.btnReset);
            this.groupBox4.Location = new System.Drawing.Point(12, 88);
            this.groupBox4.Name = "groupBox4";
            this.groupBox4.Size = new System.Drawing.Size(409, 241);
            this.groupBox4.TabIndex = 5;
            this.groupBox4.TabStop = false;
            // 
            // progressBar
            // 
            this.progressBar.Location = new System.Drawing.Point(12, 335);
            this.progressBar.Name = "progressBar";
            this.progressBar.Size = new System.Drawing.Size(824, 23);
            this.progressBar.TabIndex = 8;
            // 
            // MainFrame
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(845, 364);
            this.Controls.Add(this.progressBar);
            this.Controls.Add(this.groupBox4);
            this.Controls.Add(this.groupBox3);
            this.Controls.Add(this.groupBox2);
            this.Controls.Add(this.groupBox1);
            this.Name = "MainFrame";
            this.Load += new System.EventHandler(this.MainFrame_Load);
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.groupBox2.ResumeLayout(false);
            this.groupBox2.PerformLayout();
            this.groupBox3.ResumeLayout(false);
            this.groupBox4.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button btnSave;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.GroupBox groupBox2;
        private System.Windows.Forms.RadioButton radBlockInbound;
        private System.Windows.Forms.RadioButton radAllowInbound;
        private System.Windows.Forms.RadioButton radBlockOutbound;
        private System.Windows.Forms.RadioButton radAllowOutbound;
        private AeroListView lvLog;
        private System.Windows.Forms.Button btnReset;
        private System.Windows.Forms.Button btnHarden;
        private System.Windows.Forms.GroupBox groupBox3;
        private System.Windows.Forms.Button btnRemove;
        private System.Windows.Forms.Button btnFile;
        private System.Windows.Forms.Button btnDir;
        private AeroListView lvExclude;
        private System.Windows.Forms.GroupBox groupBox4;
        private System.Windows.Forms.ProgressBar progressBar;
    }
}

