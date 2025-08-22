using System.Threading.Tasks;

namespace ECommerceAuth.Application.Interfaces
{
    /// <summary>
    /// Interface du service d'envoi d'emails.
    /// </summary>
    /// <remarks>
    /// Ce service gère l'envoi de tous les emails du système :
    /// - Confirmation d'inscription
    /// - Réinitialisation de mot de passe
    /// - Notifications de sécurité
    /// - Codes 2FA par email (optionnel)
    /// 
    /// Avantages de l'abstraction :
    /// - Facilite les tests (mocking)
    /// - Permet de changer de provider (SMTP, SendGrid, etc.)
    /// - Centralise la logique d'envoi d'emails
    /// </remarks>
    public interface IEmailService
    {
        /// <summary>
        /// Envoie un email de confirmation d'inscription.
        /// </summary>
        /// <param name="email">Adresse email du destinataire</param>
        /// <param name="userName">Nom d'utilisateur</param>
        /// <param name="confirmationLink">Lien de confirmation</param>
        /// <returns>True si envoyé avec succès</returns>
        Task<bool> SendEmailConfirmationAsync(string email, string userName, string confirmationLink);

        /// <summary>
        /// Envoie un email de réinitialisation de mot de passe.
        /// </summary>
        /// <param name="email">Adresse email du destinataire</param>
        /// <param name="userName">Nom d'utilisateur</param>
        /// <param name="resetLink">Lien de réinitialisation</param>
        /// <returns>True si envoyé avec succès</returns>
        Task<bool> SendPasswordResetAsync(string email, string userName, string resetLink);

        /// <summary>
        /// Envoie un email de bienvenue après confirmation.
        /// </summary>
        /// <param name="email">Adresse email du destinataire</param>
        /// <param name="userName">Nom d'utilisateur</param>
        /// <returns>True si envoyé avec succès</returns>
        Task<bool> SendWelcomeEmailAsync(string email, string userName);

        /// <summary>
        /// Envoie une notification de connexion suspecte.
        /// </summary>
        /// <param name="email">Adresse email du destinataire</param>
        /// <param name="userName">Nom d'utilisateur</param>
        /// <param name="ipAddress">Adresse IP de la connexion</param>
        /// <param name="location">Localisation approximative</param>
        /// <param name="userAgent">User Agent du navigateur</param>
        /// <returns>True si envoyé avec succès</returns>
        Task<bool> SendSuspiciousLoginNotificationAsync(string email, string userName, string ipAddress, string? location = null, string? userAgent = null);

        /// <summary>
        /// Envoie un code d'authentification à deux facteurs par email.
        /// </summary>
        /// <param name="email">Adresse email du destinataire</param>
        /// <param name="userName">Nom d'utilisateur</param>
        /// <param name="code">Code 2FA</param>
        /// <returns>True si envoyé avec succès</returns>
        Task<bool> SendTwoFactorCodeAsync(string email, string userName, string code);

        /// <summary>
        /// Envoie une notification de changement de mot de passe.
        /// </summary>
        /// <param name="email">Adresse email du destinataire</param>
        /// <param name="userName">Nom d'utilisateur</param>
        /// <param name="ipAddress">Adresse IP du changement</param>
        /// <returns>True si envoyé avec succès</returns>
        Task<bool> SendPasswordChangedNotificationAsync(string email, string userName, string ipAddress);

        /// <summary>
        /// Envoie une notification de désactivation de compte.
        /// </summary>
        /// <param name="email">Adresse email du destinataire</param>
        /// <param name="userName">Nom d'utilisateur</param>
        /// <param name="reason">Raison de la désactivation</param>
        /// <returns>True si envoyé avec succès</returns>
        Task<bool> SendAccountDeactivationNotificationAsync(string email, string userName, string reason);

        /// <summary>
        /// Envoie un email générique.
        /// </summary>
        /// <param name="to">Adresse email du destinataire</param>
        /// <param name="subject">Sujet de l'email</param>
        /// <param name="htmlBody">Corps de l'email en HTML</param>
        /// <param name="textBody">Corps de l'email en texte brut (optionnel)</param>
        /// <returns>True si envoyé avec succès</returns>
        Task<bool> SendEmailAsync(string to, string subject, string htmlBody, string? textBody = null);
    }
}