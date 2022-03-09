# Script zur Anlage von Kerberos Accounts und Generierung der Krb Dateien
# Erstellt von Tobias Kuch März 2022
$Version = "1.0"
# Bugs, Ideen, Anmerkungen: keine

$UserAccountPrefix = $null
$UserAccountSuffix = $null
$ChangeName = $null
$UserNames = $null
Import-Module ActiveDirectory

#Konfiguration

$ServerNames=("testkrb","testkrb1")    # MANDATORY
$ServiceName= "HTTP"                   # MANDATORY, can be HTTP,DNS
$KeyAlgorythm  = "AES256"              # MANDATORY, can be AES256,AES128
$Domain = (Get-ADDomain).DNSRoot       # MANDATORY
$UserPath = (Get-ADOrganizationalUnit -filter { name -like "Users*"}).DistinguishedName  # MANDATORY

#$UserAccountPrefix = ""    # OPTIONAL
#$UserAccountSuffix = ""    # OPTIONAL
#$UserNames=("Alttestkrb","alttestkrb1") # OPTIONAL Alternative Usernames for Keytab uses
#$ChangeName = "CHA" # OPTIONAL

#General
$Outputpath = "C:\tmp\"

#Passwortgenerierungsparameter
$AnzahlZeichen   = 20
$Sonderzeichen   = $true  
$Zahlen          = $true
$Kleinbuchstaben = $true
$Grossbuchstaben = $true
   
# Defintion Zeichensatz
$OnlyChar = @()
$OnlyChar = 65..90  | ForEach-Object {[char] $_}
#$OnlyChar+= 97..122 | ForEach-Object {[char] $_}
$OnlyNum = @()
$OnlyNum = 0..9  | ForEach-Object {$_}

$Zeichen = $null
if ($Grossbuchstaben -eq $true) { $Zeichen += 65..90  | ForEach-Object {[char] $_} }
if ($Kleinbuchstaben -eq $true) { $Zeichen += 97..122 | ForEach-Object {[char] $_} }
if ($Zahlen          -eq $true) { $Zeichen += 0..9    | ForEach-Object { $_ }      }
if ($Sonderzeichen   -eq $true) { '!$%&()=?*+#-_' -split '' | ForEach-Object { $Zeichen += $_ } }
if ($Zeichen.count -eq 0) 
   {
   Write-Host "Der Zeichensatz darf nicht leer sein!" -ForegroundColor Magenta
   break
   }
[int] $Nindex = 0
if ( $UserNames -eq $NULL ) {$UserNames = $ServerNames}
if ( $UserAccountPrefix -eq $NULL ){[STRING]$UserAccountPrefix = ""}
clear-host
if (!(Test-Path ($Outputpath)))
    {
    write-host "Output Directory" $Outputpath "not exist!. Stop." -ForegroundColor red
    break
    }
forEach ($serverName in $ServerNames)
{
# stelle Passwort zusammen
$PWD = ( Get-Random -InputObject $OnlyChar -Count 1 ) -join ''
$PWD += ( Get-Random -InputObject $OnlyNum -Count 1 ) -join ''
$PWD += (3..$AnzahlZeichen | ForEach-Object { Get-Random -InputObject $Zeichen -Count 1 }) -join ''
$Username = $Null 
if (!($UserAccountPrefix -eq $NULL)) 
    {
    if (($UserNames).count -lt 2) { $Username =  $UserAccountPrefix + $UserNames} else {$Username = $UserAccountPrefix + $UserNames[$Nindex] }
    }
else 
    {
    if (($UserNames).count -lt 2) { $Username = $UserNames} else {$Username = $UserNames[$Nindex] }
    }

if (!($UserAccountSuffix -eq $NULL))  { $Username = $Username + $UserAccountSuffix }
$Nindex++
if (!($ChangeName -eq $NULL)) { $Description = "SSO Konfiguration für Server: " + $serverName + " - Change: " + $ChangeName }
else { $Description = "SSO Konfiguration für Server: " + $serverName }
$Secure_String_Pwd = ConvertTo-SecureString $PWD -AsPlainText -Force
$UPN =$Username + "@" +$Domain
$Error.Clear()
$UserCreated = $true
try
    {
    New-ADUser $Username -Path $UserPath -Description $Description -GivenName $Username -SamAccountName $Username -UserPrincipalName $UPN -PasswordNeverExpires $true -CannotChangePassword $true -Enabled $true -AccountPassword $Secure_String_Pwd -KerberosEncryptionType $KeyAlgorythm
    }
catch
    {
    write-host "User"$Username" cannot Created. Reason: " -NoNewline
    write-host $Error -ForegroundColor red
    $Error.Clear()
    $UserCreated = $false
    }
finally
    {
    if ($UserCreated)
        {
        try
            {
            if ($serverName -eq $Username) { $FullKeyTabFileName = $Outputpath+$ServiceName +"_"+$serverName+".krb5keytab" } else  { $FullKeyTabFileName = $Outputpath+$ServiceName +"_"+$serverName+"_for_"+ $Username +".krb5keytab" }
            $LognameFileName  = $Outputpath+$ChangeName +"CreateKeytabFiles.log"          
            Out-File -InputObject $Informations $LognameFileName -Append 
            if ($KeyAlgorythm -eq "AES256") {$crypto = "AES256-SHA1"} 
            elseif ($KeyAlgorythm -eq "AES128") {$crypto = "AES128-SHA1"} else {$crypto = "NONE" }
            $Informations ="Benutzeraccount: " + $Username + " Passwort: "+ $PWD +" Keytab Datei: " + $FullKeyTabFileName + " Kryptoalgorythmus: " + $crypto
            write-Host $Informations 
            $AltDomain = $Domain.ToUpper()
            ktpass -princ "$ServiceName/$serverName.$Domain@$AltDomain" -mapuser $UPN -pass $PWD -crypto $crypto -mapOp set -ptype KRB5_NT_PRINCIPAL -out $FullKeyTabFileName >> $LognameFileName 
            }
        catch
            {
            write-host "File" $FullKeyTabFileName" cannot Created. Reason: " -NoNewline
            write-host $Error -ForegroundColor red
            $Error.Clear()
            }
        }
    }
}
