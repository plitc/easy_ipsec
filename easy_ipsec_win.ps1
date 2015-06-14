<#

### LICENSE // ###
#
# Copyright (c) 2014-2015, Daniel Plominski (Plominski IT Consulting)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice, this
# list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
### // LICENSE ###

#>

#"run as administrator"
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments
break
}

echo '# ### ### ### ##### ### ### ### #'
echo '#                               #'
echo '# (\/)                          #'
echo '# (..)   easy_ipsec for windows #'
echo '# (")(")                        #'
echo '#                               #'
echo '# ### ### ### ##### ### ### ### #'
echo "" # dummy
Start-Sleep -s 10

echo "-> set IKE's main mode"
netsh advfirewall set global mainmode mmsecmethods dhgroup14:aes256-sha256
Start-Sleep -s 2

echo "--> set Key lifetime"
netsh advfirewall set global mainmode mmkeylifetime 10min
Start-Sleep -s 2

echo "---> enforce Diffie Hellmann"
netsh advfirewall set global mainmode mmforcedh yes
Start-Sleep -s 2

echo "----> IPsec through routers"
netsh advfirewall set global ipsec ipsecthroughnat serverandclientbehindnat
Start-Sleep -s 2



[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing1") 
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms1") 

$objForm = New-Object System.Windows.Forms1.Form 
$objForm.Text = "IPsec PreSharedKey"
$objForm.Size = New-Object System.Drawing1.Size(300,200) 
$objForm.StartPosition = "CenterScreen"

$objForm.KeyPreview = $True
$objForm.Add_KeyDown({if ($_.KeyCode -eq "Enter") 
{$x=$objTextBox.Text;$objForm.Close()}})
$objForm.Add_KeyDown({if ($_.KeyCode -eq "Escape") 
{$objForm.Close()}})

$OKButton = New-Object System.Windows.Forms1.Button
$OKButton.Location = New-Object System.Drawing1.Size(75,120)
$OKButton.Size = New-Object System.Drawing1.Size(75,23)
$OKButton.Text = "OK"
$OKButton.Add_Click({$x=$objTextBox.Text;$objForm.Close()})
$objForm.Controls.Add($OKButton)

$CancelButton = New-Object System.Windows.Forms1.Button
$CancelButton.Location = New-Object System.Drawing1.Size(150,120)
$CancelButton.Size = New-Object System.Drawing1.Size(75,23)
$CancelButton.Text = "Cancel"
$CancelButton.Add_Click({$objForm.Close()})
$objForm.Controls.Add($CancelButton)

$objLabel = New-Object System.Windows.Forms1.Label
$objLabel.Location = New-Object System.Drawing1.Size(10,20) 
$objLabel.Size = New-Object System.Drawing1.Size(280,20) 
$objLabel.Text = "Please enter the IPsec PreSharedKey:"
$objForm.Controls.Add($objLabel) 

$objTextBox = New-Object System.Windows.Forms1.TextBox 
$objTextBox.Location = New-Object System.Drawing1.Size(10,60) 
$objTextBox.Size = New-Object System.Drawing1.Size(260,20) 
$objForm.Controls.Add($objTextBox) 

$objForm.Topmost = $True

$objForm.Add_Shown({$objForm.Activate()})
[void] $objForm.ShowDialog()



echo "-----> configure the Roadwarrior connection <-----"
netsh advfirewall consec del rule name="roadwarrior"
echo "" # dummy
netsh advfirewall consec add rule name="roadwarrior" endpoint1=any endpoint2=172.31.254.0/24 action=requireinrequireout mode=tunnel enable=yes profile=any type=static localtunnelendpoint=any remotetunnelendpoint=10.0.0.1 protocol=any interfacetype=any auth1=computerpsk auth1psk="$x" qmpfs=dhgroup14 qmsecmethods="ESP:SHA256-AES256+10min+1000000000kb"
Start-Sleep -s 5

echo "" # dummy
netsh advfirewall consec show rule name="roadwarrior"
echo "" # dummy
Start-Sleep -s 5

echo "" # dummy
echo "EXIT"
Start-Sleep -s 2

