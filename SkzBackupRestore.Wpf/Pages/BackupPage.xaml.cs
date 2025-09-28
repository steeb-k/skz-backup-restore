using System.Windows.Controls;
using SkzBackupRestore.Wpf.Views;

namespace SkzBackupRestore.Wpf.Pages
{
    public partial class BackupPage : Page
    {
        public BackupPage()
        {
            InitializeComponent();
        }

        private void DiskBackup_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            var control = new DiskBackupWizard();
            var wizard = new WizardWindow
            {
                Title = "Disk Backup Wizard",
                Content = control
            };
            wizard.Owner = System.Windows.Window.GetWindow(this);
            var result = wizard.ShowDialog();
            if (result == true)
            {
                // control.SelectedDiskNumbers → pass to imaging utility in a future step
                // TODO: Launch backup flow with full disk imaging using control.SelectedDiskNumbers
            }
        }
    }
}
