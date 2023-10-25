<#PSScriptInfo
.VERSION 0.1
.GUID 6ff501e7-f9bc-4026-b6b8-07829949ef20
.AUTHOR Dominik Gilgen
.COMPANYNAME Dominik Gilgen (Personal)
.COPYRIGHT 2023 Dominik Gilgen. All rights reserved.
.LICENSEURI https://github.com/M365-Consultant/EntraID-LeakedCredentials-Notification/blob/main/LICENSE
.PROJECTURI https://github.com/M365-Consultant/EntraID-LeakedCredentials-Notification/
.EXTERNALMODULEDEPENDENCIES Microsoft.Graph.Authentication,Microsoft.Graph.Identity.SignIns,Microsoft.Graph.Users,Microsoft.Graph.Users.Actions
.RELEASENOTES
First release of this Azure Runbook
#>

<# 

.DESCRIPTION 
 Azure Runbook - Leaked Credentials Notification
 
 This script is designed for an Azure Runbook to automatically sending an e-mail when a new leaked credential risk is detected from Entra Identity Protection.

 The notifications for users can be turned on or off with the parameter. Within the function "runbookSendMailUser" are translations for multi-language support.
 Please be aware that the translations for the user-notifictions are created with AI and should be checked! Also you can add new languages in this section.

 Before running this, you need to set up an automation account with a managed identity.
 
 The managed identity requires the following Graph Permissions:
    - User.Read.All
    - IdentityRiskEvent.Read.All
    - Mail.Send

 The script requires the following modules:
    - Microsoft.Graph.Authentication
    - Microsoft.Graph.Identity.SignIns
    - Microsoft.Graph.Users
    - Microsoft.Graph.Users.Actions

 A Automation Account Variable is required to save which detections has been already handeled by the previous run:
    - Name: LeakedCredentialsNotification_lastObject
    - Type: String
    - Value: 2023-01-01T00:00:00Z

 There are a few parameters which must be set for a job run:
    - $mailSender -> The mail-alias from which the mail will be send (can be a user-account or a shared-mailbox)
    - $mailRecipients -> The recpient(s) of a mail. If you want more than one recpient, you can seperate them with ;
    - $notifyUser -> turns the user-notification on (true) or off (false)

#> 

Param
(
  [Parameter (Mandatory= $true)]
  [String] $mailSender,
  [Parameter (Mandatory= $true)]
  [String] $mailRecipients,
  [Parameter (Mandatory= $true)]
  [Boolean] $notifyUser
)

#Connect to Microsoft Graph using a Managed Identity
Connect-MgGraph -Identity

#Preparing necessary variables
$variableLastObjectTime = Get-AutomationVariable -Name 'LeakedCredentialsNotification_lastObject'
$filterEventType = "RiskEventType eq 'leakedCredentials'"
$filterEventTime = "DetectedDateTime gt " + $variableLastObjectTime.ToString('yyyy-MM-ddThh:mm:ssZ')
$mailRecipientsArray = $mailRecipients.Split(";")

#Preparing mail content
$mailContentAdminHeader = "<p style='font-weight:bold'><h3>Microsoft Identity Proction: Leaked Account Credentials</h3>Microsoft Identity Protection has detected that some user credentials have been leaked. This is a serious security issue that requires immediate attention.</p><br>"
$mailContentAdminDetails = "<p style='color: red;font-weight:bold'>Those users are affected:</p><table style='width: 100%'><colgroup><col span='1' style='width: 25%;'><col span='1' style='width: 30%;'><col span='1' style='width: 45%;'></colgroup><thead><tr><th style='text-align: left'>Detected at UTC</th><th style='text-align: left'>User</th><th style='text-align: left'>UPN</th></tr></thead><tbody>"

#Mail function - Admin Notification
function runbookSendMailAdmin {
    $mailSubject = "Alert: Leaked Credentials"
    $mailContentAdminFooter = "<br><br><p style='color: grey'>You can find additional details in the job history of this runbook.<br>Job finished at (UTC) " + (Get-Date).ToUniversalTime() + "<br>Job ID:"+ $PSPrivateMetadata.JobId.Guid + "</p>"
    $mailContentAdmin = $mailContentAdminHeader + $mailContentAdminDetails + $mailContentAdminFooter
   
  
    $paramsAdminMail = @{
            Message = @{
                Subject = $mailSubject
                Importance = "High"
                Body = @{
                    ContentType = "html"
                    Content = $mailContentAdmin
                }
                ToRecipients = @(
                    foreach ($recipient in $mailRecipientsArray) {
                        @{
                            EmailAddress = @{
                                Address = $recipient
                            }
                        }
                    }
                )
            }
            SaveToSentItems = "false"
        }
        
    Send-MgUserMail -UserId $mailSender -BodyParameter $paramsAdminMail
    Write-Output "Sending admin mail..."
  }

#Mail function - User Notification
  function runbookSendMailUser {
    param (
        $MailUserRecipient,
        $MailUserDetectionTime,
        $MailUserPreferredLanguage
    )

    # Setting default language for users with no preferred language set
    if (!$MailUserPreferredLanguage) { $MailUserPreferredLanguage = "en-US" }
 
    # Translations for the users mail content (use HTML!)
    $mailContentUserTranslations = @{
        "en-US" = "<p style='font-weight:bold'><h3>Microsoft Identity Protection: Leaked Account Credentials</h3>Microsoft Identity Protection has detected at $MailUserDetectionTime (UTC) that your credentials have been leaked on the internet.<br>This is a serious security issue that requires immediate attention.</p><br><br><h3>Remediation Recommendations</h3><ol type='1'><li><b>Reset your password: </b>Since your credentials have been leaked, it is important to reset your password immediately. This will prevent unauthorized access to our organization’s resources and data.</li><li><b>Contact IT-Helpdesk: </b>Please contact our IT-Helpdesk and make yourself ready to be rescued. We would help you identify potential security threats and take appropriate action.</li><li><b>Check your actitivies: </b>On your <a href='https://mysignins.microsoft.com/'>MySignins-Portal</a> you can check you recent account activities. If there is anythink looking unfamiliar to you, please get in touch with the IT-Helpdesk</li><li><b>Multi-Faktor Authentification: </b>Check your Two-factor authentication on your <a href='https://mysignins.microsoft.com/security-info'>Account Page</a> and use Microsoft Authenticator as prefered method.</li><li><b>Check other accounts: </b>Think about where else you may have used the same password. If you reused your password there, you should change it there too. If available, please set up MFA also on third-party tools and websites. Also, a Password-Manager can help you use secure and unique passwords.<li><b>Be aware of phishing:</b> Please be aware of phishing scams and malicious emails. If you have any concerns, feel free to contact the IT-Helpdesk.</li></ol>"
        "en-GB" = "<p style='font-weight:bold'><h3>Microsoft Identity Protection: Leaked Account Credentials</h3>Microsoft Identity Protection has detected at $MailUserDetectionTime (UTC) that your credentials have been leaked on the internet.<br>This is a serious security issue that requires immediate attention.</p><br><br><h3>Remediation Recommendations</h3><ol type='1'><li><b>Reset your password: </b>Since your credentials have been leaked, it is important to reset your password immediately. This will prevent unauthorized access to our organization’s resources and data.</li><li><b>Contact IT-Helpdesk: </b>Please contact our IT-Helpdesk and make yourself ready to be rescued. We would help you identify potential security threats and take appropriate action.</li><li><b>Check your actitivies: </b>On your <a href='https://mysignins.microsoft.com/'>MySignins-Portal</a> you can check you recent account activities. If there is anythink looking unfamiliar to you, please get in touch with the IT-Helpdesk</li><li><b>Multi-Faktor Authentification: </b>Check your Two-factor authentication on your <a href='https://mysignins.microsoft.com/security-info'>Account Page</a> and use Microsoft Authenticator as prefered method.</li><li><b>Check other accounts: </b>Think about where else you may have used the same password. If you reused your password there, you should change it there too. If available, please set up MFA also on third-party tools and websites. Also, a Password-Manager can help you use secure and unique passwords.<li><b>Be aware of phishing:</b> Please be aware of phishing scams and malicious emails. If you have any concerns, feel free to contact the IT-Helpdesk.</li></ol>"
        "de-DE" = "<p style='font-weight:bold'><h3>Microsoft Identity Protection: Leaked Account Credentials</h3>Microsoft Identity Protection hat festgestellt, dass Ihre Anmeldeinformationen am $MailUserDetectionTime (UTC) im Internet veröffentlicht wurden.<br>Dies ist ein ernstes Sicherheitsproblem, das sofortige Aufmerksamkeit erfordert.</p><br><br><h3>Empfohlene Schritte</h3><ol type=‘1’><li><b>Setzen Sie Ihr Passwort zurück: </b>Da Ihre Anmeldeinformationen wurden im Internet veröffentlicht, ist es wichtig, Ihr Passwort sofort zurückzusetzen. Dadurch wird verhindert, dass auf die Ressourcen und Daten unserer Organisation unbefugt zugegriffen wird.</li><li><b>Kontaktieren Sie den IT-Helpdesk: </b>Bitte kontaktieren Sie unseren IT-Helpdesk und machen Sie sich bereit, gerettet zu werden. Wir helfen Ihnen dabei, potenzielle Sicherheitsbedrohungen zu identifizieren und geeignete Maßnahmen zu ergreifen.</li><li><b>Überprüfen Sie Ihre Aktivitäten: </b>Auf Ihrem <a href=‘https://mysignins.microsoft.com/’>MySignins-Portal</a> können Sie Ihre kürzlichen Kontenaktivitäten überprüfen. Wenn Ihnen etwas auffällig erscheint, setzen Sie sich bitte mit dem IT-Helpdesk in Verbindung.</li><li><b>Mehrstufige Authentifizierung: </b>Überprüfen Sie Ihre Zwei-Faktor-Authentifizierung auf Ihrer <a href=‘https://mysignins.microsoft.com/security-info’>Kontoseite</a> und verwenden Sie Microsoft Authenticator als bevorzugte Methode.</li><li><b>Überprüfen Sie andere Konten: </b>Überlegen Sie, wo Sie möglicherweise dasselbe Passwort verwendet haben. Wenn Sie Ihr Passwort dort wiederverwendet haben, sollten Sie es auch dort ändern. Wenn verfügbar, richten Sie eine MFA auch für Tools und Websites von Drittanbietern ein. Ein Passwort-Manager kann Ihnen auch dabei helfen, sichere und einzigartige Passwörter zu verwenden.<li><b>Achten Sie auf Phishing:</b> Bitte achten Sie auf Phishing-Betrug und bösartige E-Mails. Wenn Sie Bedenken haben, wenden Sie sich bitte im Zweifelsfall an den IT-Helpdesk.</li></ol>"
        "nl-NL" = "<p style='font-weight:bold'><h3>Microsoft Identity Protection: Leaked Account Credentials</h3>Microsoft Identity Protection heeft gedetecteerd dat uw referenties op het internet zijn gelekt om $MailUserDetectionTime (UTC).<br>Dit is een ernstig beveiligingsprobleem dat onmiddellijke aandacht vereist.</p><br><br><h3>Aanbevelingen voor herstel</h3><ol type=‘1’><li><b>Reset uw wachtwoord: </b>Aangezien uw referenties zijn gelekt, is het belangrijk om uw wachtwoord onmiddellijk te resetten. Dit voorkomt ongeautoriseerde toegang tot de bronnen en gegevens van onze organisatie.</li><li><b>Contact IT-Helpdesk: </b>Neem contact op met onze IT-Helpdesk en maak uzelf klaar om gered te worden. We zouden u helpen potentiële beveiligingsbedreigingen te identificeren en passende maatregelen te nemen.</li><li><b>Controleer uw activiteiten: </b>Op uw <a href=‘https://mysignins.microsoft.com/’>MySignins-Portal</a> kunt u uw recente accountactiviteiten controleren. Als er iets onbekends opvalt, neem dan contact op met de IT-Helpdesk</li><li><b>Multi-Faktor Authenticatie: </b>Controleer uw Tweefactorauthenticatie op uw <a href=‘https://mysignins.microsoft.com/security-info’>Accountpagina</a> en gebruik Microsoft Authenticator als voorkeursmethode.</li><li><b>Controleer andere accounts: </b>Denk na over waar u mogelijk hetzelfde wachtwoord hebt gebruikt. Als u uw wachtwoord daar hebt hergebruikt, moet u het daar ook wijzigen. Als dit beschikbaar is, stelt u MFA ook in voor tools en websites van derden. Een wachtwoordbeheerder kan u ook helpen bij het gebruik van veilige en unieke wachtwoorden.<li><b>Wees alert op phishing:</b> Wees alert op phishing scams en kwaadaardige e-mails. Als u zich zorgen maakt, neem dan gerust contact op met de IT-Helpdesk.</li></ol>"
        "fr-FR" = "<p style='font-weight:bold'><h3>Microsoft Identity Protection: Leaked Account Credentials</h3>Microsoft Identity Protection a détecté à $MailUserDetectionTime (UTC) que vos informations d’identification ont été divulguées sur Internet.<br>Ceci est un problème de sécurité grave qui nécessite une attention immédiate.</p><br><br><h3>Recommandations de remédiation</h3><ol type=‘1’><li><b>Réinitialisez votre mot de passe: </b>Étant donné que vos informations d’identification ont été divulguées, il est important de réinitialiser votre mot de passe immédiatement. Cela empêchera l’accès non autorisé aux ressources et données de notre organisation.</li><li><b>Contactez le service d’assistance informatique: </b>Veuillez contacter notre service d’assistance informatique et vous préparer à être secouru. Nous vous aiderions à identifier les menaces potentielles pour la sécurité et à prendre les mesures appropriées.</li><li><b>Vérifiez vos activités: </b>Sur votre <a href=‘https://mysignins.microsoft.com/’>portail MySignins</a>, vous pouvez vérifier vos activités de compte récentes. Si quelque chose vous semble inhabituel, veuillez contacter le service d’assistance informatique.</li><li><b>Authentification multi-facteurs: </b>Vérifiez votre authentification à deux facteurs sur votre <a href=‘https://mysignins.microsoft.com/security-info’>page de compte</a> et utilisez Microsoft Authenticator comme méthode préférée.</li><li><b>Vérifiez les autres comptes: </b>Réfléchissez à l’endroit où vous avez peut-être utilisé le même mot de passe. Si vous avez réutilisé votre mot de passe là-bas, vous devriez également le changer là-bas. Si possible, configurez également MFA sur des outils et des sites Web tiers. De plus, un gestionnaire de mots de passe peut vous aider à utiliser des mots de passe sécurisés et uniques.<li><b>Soyez conscient du phishing:</b> Veuillez être conscient des escroqueries par phishing et des e-mails malveillants. Si vous avez des préoccupations, n’hésitez pas à contacter le service d’assistance informatique.</li></ol>"
        "es-ES" = "<p style='font-weight:bold'><h3>Microsoft Identity Protection: Leaked Account Credentials</h3>Microsoft Identity Protection ha detectado en $MailUserDetectionTime (UTC) que sus credenciales se han filtrado en Internet.<br>Este es un problema de seguridad grave que requiere atención inmediata.</p><br><br><h3>Recomendaciones de remedio</h3><ol type=‘1’><li><b>Restablezca su contraseña: </b>Dado que sus credenciales se han filtrado, es importante restablecer su contraseña de inmediato. Esto evitará el acceso no autorizado a los recursos y datos de nuestra organización.</li><li><b>Contacte con el servicio de asistencia técnica: </b>Póngase en contacto con nuestro servicio de asistencia técnica y prepárese para ser rescatado. Le ayudaríamos a identificar posibles amenazas de seguridad y a tomar medidas apropiadas.</li><li><b>Compruebe sus actividades: </b>En su <a href=‘https://mysignins.microsoft.com/’>portal MySignins</a>, puede comprobar sus actividades recientes en la cuenta. Si ve algo que le resulte desconocido, póngase en contacto con el servicio de asistencia técnica.</li><li><b>Autenticación multifactorial: </b>Compruebe su autenticación de dos factores en su <a href=‘https://mysignins.microsoft.com/security-info’>página de cuenta</a> y utilice Microsoft Authenticator como método preferido.</li><li><b>Compruebe otras cuentas: </b>Piense en dónde más puede haber utilizado la misma contraseña. Si reutilizó su contraseña allí, también debería cambiarla allí. Si está disponible, configure MFA también en herramientas y sitios web de terceros. Además, un administrador de contraseñas puede ayudarle a utilizar contraseñas seguras y únicas.<li><b>Tenga cuidado con el phishing:</b> Tenga cuidado con las estafas de phishing y los correos electrónicos malintencionados. Si tiene alguna preocupación, no dude en ponerse en contacto con el servicio de asistencia técnica.</li></ol>"
        "it-IT" = "<p style='font-weight:bold'><h3>Microsoft Identity Protection: Leaked Account Credentials</h3>Microsoft Identity Protection ha rilevato che le tue credenziali sono state divulgate su Internet alle $MailUserDetectionTime (UTC).<br>Si tratta di un problema di sicurezza grave che richiede un’attenzione immediata.</p><br><br><h3>Raccomandazioni per la correzione</h3><ol type=‘1’><li><b>Reimposta la tua password: </b>Dato che le tue credenziali sono state divulgate, è importante reimpostare immediatamente la tua password. Ciò impedirà l’accesso non autorizzato alle risorse e ai dati della nostra organizzazione.</li><li><b>Contatta l’IT-Helpdesk: </b>Contatta il nostro IT-Helpdesk e preparati a essere salvato. Ti aiuteremo a identificare le potenziali minacce alla sicurezza e ad adottare le misure appropriate.</li><li><b>Controlla le tue attività: </b>Sul tuo <a href=‘https://mysignins.microsoft.com/’>portale MySignins</a>, puoi controllare le tue attività recenti dell’account. Se noti qualcosa di sconosciuto, contatta l’IT-Helpdesk</li><li><b>Autenticazione multi-fattore: </b>Controlla la tua autenticazione a due fattori sulla tua <a href=‘https://mysignins.microsoft.com/security-info’>pagina dell’account</a> e utilizza Microsoft Authenticator come metodo preferito.</li><li><b>Controlla gli altri account: </b>Pensa a dove altro potresti aver usato la stessa password. Se hai riutilizzato la tua password lì, dovresti cambiarla anche lì. Se disponibile, configura anche MFA su strumenti e siti Web di terze parti. Inoltre, un gestore di password può aiutarti a utilizzare password sicure e uniche.<li><b>Sii consapevole del phishing:</b> Sii consapevole delle truffe di phishing e delle email maligne. Se hai qualche preoccupazione, non esitare a contattare l’IT-Helpdesk.</li></ol>"
    }
    
    # Translations for the users mail subject 
    $mailSubjectTranslations = @{
        "en-US" = "Attention: Your credentials got leaked"
        "en-GB" = "Attention: Your credentials got leaked"
        "de-DE" = "Achtung: Ihre Zugangsdaten wurden veröffentlicht"
        "nl-NL" = "Aandacht: Uw inloggegevens zijn openbaar gemaakt."
        "fr-FR" = "Attention: Vos informations d’identification ont été publiées."
        "es-ES" = "Atención: Sus credenciales de acceso han sido publicadas."
        "it-IT" = "Attenzione: le tue credenziali di accesso sono state pubblicate."
    }

    # Setting the content based on the users preferred language. If their is no translation the default will be en-US.
    if ($mailContentUserTranslations.ContainsKey($MailUserPreferredLanguage)) { $mailContentUser = $mailContentUserTranslations[$MailUserPreferredLanguage] }
    else { $mailContentUser = $mailContentUserTranslations["en-US"] }

    if ($mailSubjectTranslations.ContainsKey($MailUserPreferredLanguage)) { $mailSubject = $mailSubjectTranslations[$MailUserPreferredLanguage] }
    else { $mailSubject = $mailSubjectTranslations["en-US"] }

    
    $paramsUserMail = @{
            Message = @{
                Subject = $mailSubject
                Importance = "High"
                Body = @{
                    ContentType = "html"
                    Content = $mailContentUser
                }
                ToRecipients = @(
                        @{
                            EmailAddress = @{
                                Address = $MailUserRecipient
                            }
                        }
                )
                CcRecipients = @(
                    foreach ($recipient in $mailRecipientsArray) {
                        @{
                            EmailAddress = @{
                                Address = $recipient
                            }
                        }
                    }
                )
            }
            SaveToSentItems = "false"
        }
        
    Send-MgUserMail -UserId $mailSender -BodyParameter $paramsUserMail
    Write-Output "Sending user mail to $MailUserRecipient"
  }

#Getting all new leaked credential events
$riskDetections = Get-MgRiskDetection -All -Filter "$filterEventType and $filterEventTime"
foreach ($event in $riskDetections)
{
    #Gathering user details (required for the user-mail)
    $userDetails = Get-MgUser -UserId $event.UserId | Select-Object DisplayName,UserPrincipalName,Mail,PreferredLanguage
    
    #Creating a entry on the mail-content
    $mailContentAdminObject = "<tr><td>"+$event.DetectedDateTime+"</td><td>"+$event.UserDisplayName+"</td><td>"+$event.UserPrincipalName+"</td></tr>"
    $mailContentAdminDetails += $mailContentAdminObject

    #Creating a output-message
    $outputMessage = "Leaked credenials found for " + $event.UserDisplayName + " | " + $event.UserPrincipalName
    Write-Output $outputMessage

    #Sending the user-mail
    If ($notifyUser -eq "True") {runbookSendMailUser -MailUserRecipient $userDetails.Mail -MailUserDetectionTime $event.DetectedDateTime -MailUserPreferredLanguage $userDetails.PreferredLanguage}

}

# Closing the mail-content detail section.
$mailContentAdminDetails += "</tbody></table><br><p>Go to Entra Admin Center for more details: <a href='https://entra.microsoft.com/#view/Microsoft_AAD_IAM/SecurityMenuBlade/~/RiskDetections/'>Entra Risk Detections</a></p><br><h3>Remediation Recommendations</h3><ol type='1'><li><b>Reset the passwords of affected users:</b> If you detect that a user’s credentials have been leaked, reset their password immediately. This will prevent unauthorized access to your organization’s resources and data.</li><li><b>Monitor sign-in activity:</b>Use Azure AD Identity Protection to monitor sign-in activity and detect suspicious sign-in attempts. This can help you identify potential security threats and take appropriate action.</li><li><b>Inform users:</b> Inform your users about the importance of strong passwords, avoiding phishing scams, and other best practices for maintaining good security hygiene. Also, advise them to consider changing their passwords in other places where they used the same password.</li><li><b>Multi-factor authentication (MFA):</b> Check the users MFA and make sure your MFA setup is phishing resistant. This can help prevent unauthorized access even if a user’s credentials are compromised.</li><li><b>Review your security policies:</b> Review your organization’s security policies and ensure that they are up-to-date and effective in protecting your resources and data. Implementing Risky User Policies (E5 License / EntraID P2) is highly recommended!</li></ol>"


# Check if there are new risks detectet, and if so, send the admin-mail and update the lastObject Automation-Variable with the timestamp of the last object of this run.
if($riskDetections){
  runbookSendMailAdmin
  $automationvariableValue = $riskDetections.DetectedDateTime | Select-Object -Last 1
  Set-AutomationVariable -Name 'LeakedCredentialsNotification_lastObject' -Value $automationvariableValue
}
else{Write-Output "No new leaked credential events found."}

#Disconnect from Microsoft Graph within Azure Automation
Disconnect-MgGraph
