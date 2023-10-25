# EntraID-LeakedCredentials-Notification
 This script is designed for an Azure Runbook to automatically sending an e-mail when a new leaked credential risk is detected from Entra Identity Protection.

# Muli-Language support
 The notifications for users can be turned on or off with the parameter. Within the function "runbookSendMailUser" are translations for multi-language support.
 
 Please be aware that the translations for the user-notifictions are created with AI and should be checked! Also you can add new languages in this section.

# Requirements
Before running the runbook, you need to set up an automation account with a managed identity.

The managed identity requires the following Graph Permissions:
   - User.Read.All
   - IdentityRiskEvent.Read.All
   - Mail.Send

The script requires the following modules:
   - Microsoft.Graph.Authentication
   - Microsoft.Graph.Identity.SignIns
   - Microsoft.Graph.Users
   - Microsoft.Graph.Users.Actions

# Variable (Automation Account)
 This Automation Account Variable is required to save which detections has been already handeled by the previous run:
- Name: LeakedCredentialsNotification_lastObject
- Type: String
- Value: 2023-01-01T00:00:00Z

# Parameters
There are a few parameters which must be set for a job run:
- $mailSender
  - The mail-alias from which the mail will be send (can be a user-account or a shared-mailbox)
- $mailRecipients
  - The recipient(s) of the mail (internal or external). If you want more than one recipient, you can separate them with the character ; in between.
- $notifyUser
  - turns the user-notification on (true) or off (false)

# Changelog
- v0.1 First release
  - First release of this script
