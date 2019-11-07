###################################################################################
# PowerShell WPF Password Changer                                                 #
#                                                                                 #
# Copyright (c) PhasedLogix, LLC. All rights reserved.                            #
#                                                                                 #
# MIT License                                                                     #
#                                                                                 #
# Permission is hereby granted, free of charge, to any person obtaining a copy    #
# of this software and associated documentation files (the ""Software""), to deal #
# in the Software without restriction, including without limitation the rights    #
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell       #
# copies of the Software, and to permit persons to whom the Software is           #
# furnished to do so, subject to the following conditions:                        #
#                                                                                 #
# The above copyright notice and this permission notice shall be included in all  #
# copies or substantial portions of the Software.                                 #
#                                                                                 #
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR      #
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,        #
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE     #
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER          #
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,   #
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE   #
# SOFTWARE.                                                                       #
###################################################################################

##################################################
# ENV Setup
##################################################
function Initialize-Environment {
    [System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
    $Global:MinPasswordAge = 30 #Number of days to start warning.
    $Global:MaxPasswordAge = 40 #Number of days to force password change.
    $Global:ApplicationPath = "CC:\Program Files\Windows NT\Accessories\wordpad.exe" # Application to start
}



##################################################
# Functions
##################################################
function LoadXml ($global:filename) {
    $XamlLoader = (New-Object System.Xml.XmlDocument)
    $XamlLoader.Load($filename)
    return $XamlLoader
}
function OnLoad() {
    $pbNewPassword1.IsEnabled = $false
    $pbNewPassword2.IsEnabled = $false
    $btnChange.IsEnabled = $false
    if (($PwdLastSetDays -ge $MinPasswordAge) -or ($PwdLastSetDays -ge $MaxPasswordAge)) {
        if ($PwdLastSetDays -ge $MinPasswordAge) {
            $lblMessage.Content = "***WARNING***"
            $tbxMessage.Text = "Your password will expire in $($PwdExpire) days. Please change your password now or click Cancel to continue."
        }
        if ($PwdLastSetDays -ge $MaxPasswordAge) {
            $lblMessage.Content = "***WARNING***"
            $tbxMessage.Text = "Your password is about to expire. You must change your password now."
            $btnCancel.IsEnabled = $false
        }
    }
}
function btnChange_Click() {
    if (!($NewPassword1 -eq $NewPassword2)) {

        $lblMessage.Content = "***WARNING***"
        $tbxMessage.Text = "Passwords do not match"
    }
    else {
        $lblMessage.Forground = "Black"
        tbxMessage.Forground = "Black"
        $lblMessage.Content = "***Working....***"
        $tbxMessage.Text = "Pleasw wait, trying to change password."
        try {
            $User = $UserObject.GetDirectoryEntry()
            $User.psbase.invoke("ChangePassword",$ExistingPassword, $NewPassword1)
            $Window.Close()
            Start-Process $ApplicationPath
        }
        catch {
            $lblMessage.Content = "***ERROR***"
            $tbxMessage.Text = $_.Exception.InnerException.Message
        }
    }
}
function Get-CurrentIdentity {
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
}

function Get-ADUser {
    param ([string]$UserName)
    $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $Root = [ADSI] "LDAP://$($ADDomain.Name)"
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher $Root
    $Searcher.Filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$UserName))"
    $Searcher.FindOne()
}

##################################################
# Main
##################################################
try {
    Initialize-Environment
    $Global:UserIdentity = Get-CurrentIdentity
    $Global:UsersAMAccountName = (($UserIdentity.Identity.Name).Split("\"))[1]
    $Global:UserObject = Get-ADUser $UsersAMAccountName
    $Global:PwdLastSet = [datetime]::FromFileTime($UserObject.properties.pwdlastset[0])
    $Global:PwdLastSetDays = (([System.DateTime]::Now) - $PwdLastSet).TotalDays
    $Global:PwdExpire = "{0:N0}" -f ($MaxPasswordAge - $PwdLastSetDays)
    $Global:ExistingPassword
    $Global:NewPassword1
    $Global:NewPassword2

    
    if($PwdLastSetDays -ge $MinPasswordAge) {
        $XamlMainWindow = LoadXml("PWReset.xaml")
        $reader = (New-Object System.Xml.XmlNodeReader $XamlMainWindow)
        $Window = [Windows.Markup.XamlReader]::Load($reader)
        $btnCancel = $Window.FindName("btnCancel")
        $btnChange = $Window.FindName("btnChange")
        $pbExistingPassword = $Window.FindName("pbExistingPassword")
        $pbNewPassword1 = $Window.FindName("pbNewPassword1")
        $pbNewPassword2 = $Window.FindName("pbNewPassword2")
        $lblMessage = $Window.FindName("lblMessage")
        $tbxMessage = $Window.FindName("tbxMessage")
        $Window.Add_Loaded({OnLoad})
        $btnCancel.Add_Click({$Window.Close(); Start-Process $ApplicationPath})
        $btnChange.Add_Click({btnChange_Click})
        $pbExistingPassword.Add_PasswordChanged({
            $pbNewPassword1.IsEnabled = $true
            $pbNewPassword2.IsEnabled = $true
            $btnChange.IsEnabled = $true
            $Global:ExistingPassword = $this.password
        })
        $pbNewPassword1.Add_PasswordChanged({$Global:NewPassword1 = $this.password})
        $pbNewPassword2.Add_PasswordChanged({$Global:NewPassword2 = $this.password})
        $Window.ShowDialog()
    }
    else {
        # Start application
        Start-Process $ApplicationPath
    }
    Write-Output "Success!"

}
catch {
    # Start application
    Start-Process $ApplicationPath
}



