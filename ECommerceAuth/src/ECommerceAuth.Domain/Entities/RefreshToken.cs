using System;

namespace ECommerceAuth.Domain.Entities
{
    /// <summary>
    /// Entité représentant un token de rafraîchissement JWT.
    /// </summary>
    /// <remarks>
    /// Les refresh tokens permettent :
    /// - Une sécurité renforcée avec des JWT à courte durée de vie
    /// - La possibilité de révoquer l'accès sans blacklist des JWT
    /// - Une meilleure expérience utilisateur (pas de re-login fréquent)
    /// 
    /// Stratégie de sécurité :
    /// - Durée de vie longue (7-30 jours) mais révocable
    /// - Stockage sécurisé côté serveur
    /// - Rotation automatique à chaque utilisation (optionnel)
    /// - Limitation du nombre de tokens actifs par utilisateur
    /// </remarks>
    public class RefreshToken : BaseEntity
    {
        /// <summary>
        /// Token de rafraîchissement (chaîne aléatoire sécurisée).
        /// </summary>
        public string Token { get; set; } = string.Empty;

        /// <summary>
        /// Date d'expiration du token.
        /// </summary>
        public DateTime ExpiresAt { get; set; }

        /// <summary>
        /// Indique si le token a été révoqué.
        /// </summary>
        public bool IsRevoked { get; set; }

        /// <summary>
        /// Date de révocation du token.
        /// </summary>
        public DateTime? RevokedAt { get; set; }

        /// <summary>
        /// Raison de la révocation (déconnexion, sécurité, etc.).
        /// </summary>
        public string? RevocationReason { get; set; }

        /// <summary>
        /// Adresse IP depuis laquelle le token a été créé.
        /// </summary>
        public string? CreatedByIp { get; set; }

        /// <summary>
        /// Adresse IP depuis laquelle le token a été révoqué.
        /// </summary>
        public string? RevokedByIp { get; set; }

        /// <summary>
        /// User Agent du navigateur/application qui a créé le token.
        /// </summary>
        public string? UserAgent { get; set; }

        /// <summary>
        /// Identifiant de l'utilisateur propriétaire du token.
        /// </summary>
        public Guid UserId { get; set; }

        /// <summary>
        /// Navigation property vers l'utilisateur.
        /// </summary>
        public virtual User User { get; set; } = null!;

        /// <summary>
        /// Constructeur par défaut.
        /// </summary>
        public RefreshToken() : base()
        {
            IsRevoked = false;
        }

        /// <summary>
        /// Constructeur avec paramètres.
        /// </summary>
        /// <param name="userId">ID de l'utilisateur</param>
        /// <param name="token">Token de rafraîchissement</param>
        /// <param name="expiresAt">Date d'expiration</param>
        /// <param name="createdByIp">Adresse IP de création</param>
        /// <param name="userAgent">User Agent</param>
        public RefreshToken(Guid userId, string token, DateTime expiresAt, string? createdByIp = null, string? userAgent = null) : base()
        {
            UserId = userId;
            Token = token;
            ExpiresAt = expiresAt;
            CreatedByIp = createdByIp;
            UserAgent = userAgent;
            IsRevoked = false;
        }

        /// <summary>
        /// Vérifie si le token est actif (non expiré et non révoqué).
        /// </summary>
        public bool IsActive => !IsRevoked && DateTime.UtcNow < ExpiresAt;

        /// <summary>
        /// Révoque le token.
        /// </summary>
        /// <param name="revokedByIp">Adresse IP de révocation</param>
        /// <param name="reason">Raison de la révocation</param>
        public void Revoke(string? revokedByIp = null, string? reason = null)
        {
            IsRevoked = true;
            RevokedAt = DateTime.UtcNow;
            RevokedByIp = revokedByIp;
            RevocationReason = reason;
        }
    }
}