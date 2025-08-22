using System;

namespace ECommerceAuth.Domain.Entities
{
    /// <summary>
    /// Entité pour l'historique et l'audit des connexions utilisateur.
    /// </summary>
    /// <remarks>
    /// Cette entité permet :
    /// - L'audit de sécurité (qui se connecte, quand, depuis où)
    /// - La détection d'activités suspectes
    /// - Le respect des réglementations (RGPD, etc.)
    /// - L'analyse des patterns de connexion
    /// 
    /// Informations collectées :
    /// - Horodatage précis de la connexion
    /// - Adresse IP pour géolocalisation et sécurité
    /// - User Agent pour identifier le navigateur/device
    /// - Statut de la tentative (succès/échec)
    /// - Raison en cas d'échec
    /// </remarks>
    public class LoginHistory : BaseEntity
    {
        /// <summary>
        /// Identifiant de l'utilisateur qui tente de se connecter.
        /// </summary>
        public Guid UserId { get; set; }

        /// <summary>
        /// Adresse IP depuis laquelle la connexion a été tentée.
        /// </summary>
        public string IpAddress { get; set; } = string.Empty;

        /// <summary>
        /// User Agent du navigateur/application utilisé.
        /// </summary>
        public string? UserAgent { get; set; }

        /// <summary>
        /// Indique si la tentative de connexion a réussi.
        /// </summary>
        public bool IsSuccessful { get; set; }

        /// <summary>
        /// Raison de l'échec de connexion (mot de passe incorrect, compte verrouillé, etc.).
        /// </summary>
        public string? FailureReason { get; set; }

        /// <summary>
        /// Pays déterminé à partir de l'adresse IP (optionnel).
        /// </summary>
        public string? Country { get; set; }

        /// <summary>
        /// Ville déterminée à partir de l'adresse IP (optionnel).
        /// </summary>
        public string? City { get; set; }

        /// <summary>
        /// Informations sur l'appareil utilisé (mobile, desktop, etc.).
        /// </summary>
        public string? DeviceInfo { get; set; }

        /// <summary>
        /// Durée de la session en minutes (pour les connexions réussies).
        /// </summary>
        public int? SessionDurationMinutes { get; set; }

        /// <summary>
        /// Date de fin de session (déconnexion).
        /// </summary>
        public DateTime? SessionEndedAt { get; set; }

        /// <summary>
        /// Navigation property vers l'utilisateur.
        /// </summary>
        public virtual User User { get; set; } = null!;

        /// <summary>
        /// Constructeur par défaut.
        /// </summary>
        public LoginHistory() : base()
        {
        }

        /// <summary>
        /// Constructeur pour une tentative de connexion.
        /// </summary>
        /// <param name="userId">ID de l'utilisateur</param>
        /// <param name="ipAddress">Adresse IP</param>
        /// <param name="userAgent">User Agent</param>
        /// <param name="isSuccessful">Succès de la connexion</param>
        /// <param name="failureReason">Raison de l'échec</param>
        public LoginHistory(Guid userId, string ipAddress, string? userAgent, bool isSuccessful, string? failureReason = null) : base()
        {
            UserId = userId;
            IpAddress = ipAddress;
            UserAgent = userAgent;
            IsSuccessful = isSuccessful;
            FailureReason = failureReason;
        }

        /// <summary>
        /// Marque la fin de session.
        /// </summary>
        public void EndSession()
        {
            SessionEndedAt = DateTime.UtcNow;
            if (SessionEndedAt.HasValue)
            {
                SessionDurationMinutes = (int)(SessionEndedAt.Value - CreatedAt).TotalMinutes;
            }
        }

        /// <summary>
        /// Vérifie si la connexion est suspecte (critères basiques).
        /// </summary>
        public bool IsSuspicious
        {
            get
            {
                // Exemples de critères suspects (à adapter selon les besoins)
                return !IsSuccessful && 
                       (FailureReason?.Contains("brute force") == true ||
                        FailureReason?.Contains("too many attempts") == true);
            }
        }
    }
}