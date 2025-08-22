using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using ECommerceAuth.Domain.Entities;

namespace ECommerceAuth.Application.Interfaces
{
    /// <summary>
    /// Interface du service de gestion des tokens JWT.
    /// </summary>
    /// <remarks>
    /// Ce service gère :
    /// - Génération des tokens JWT d'accès
    /// - Génération des refresh tokens
    /// - Validation et parsing des tokens
    /// - Révocation des tokens
    /// 
    /// Sécurité des tokens :
    /// - JWT signés avec clé secrète forte
    /// - Durée de vie courte pour les access tokens (15-30 min)
    /// - Durée de vie longue pour les refresh tokens (7-30 jours)
    /// - Possibilité de révocation côté serveur
    /// </remarks>
    public interface ITokenService
    {
        /// <summary>
        /// Génère un token JWT d'accès pour un utilisateur.
        /// </summary>
        /// <param name="user">Utilisateur pour lequel générer le token</param>
        /// <param name="roles">Rôles de l'utilisateur</param>
        /// <returns>Token JWT signé</returns>
        Task<string> GenerateAccessTokenAsync(User user, IEnumerable<string> roles);

        /// <summary>
        /// Génère un token de rafraîchissement sécurisé.
        /// </summary>
        /// <param name="userId">ID de l'utilisateur</param>
        /// <param name="ipAddress">Adresse IP de création</param>
        /// <param name="userAgent">User Agent du client</param>
        /// <param name="rememberMe">Durée de vie étendue si true</param>
        /// <returns>Entité RefreshToken créée</returns>
        Task<RefreshToken> GenerateRefreshTokenAsync(Guid userId, string ipAddress, string? userAgent = null, bool rememberMe = false);

        /// <summary>
        /// Valide et parse un token JWT.
        /// </summary>
        /// <param name="token">Token JWT à valider</param>
        /// <returns>ClaimsPrincipal si valide, null sinon</returns>
        ClaimsPrincipal? ValidateToken(string token);

        /// <summary>
        /// Extrait l'ID utilisateur d'un token JWT.
        /// </summary>
        /// <param name="token">Token JWT</param>
        /// <returns>ID utilisateur ou null si invalide</returns>
        Guid? GetUserIdFromToken(string token);

        /// <summary>
        /// Extrait les rôles d'un token JWT.
        /// </summary>
        /// <param name="token">Token JWT</param>
        /// <returns>Liste des rôles</returns>
        IEnumerable<string> GetRolesFromToken(string token);

        /// <summary>
        /// Vérifie si un token JWT est expiré.
        /// </summary>
        /// <param name="token">Token JWT</param>
        /// <returns>True si expiré</returns>
        bool IsTokenExpired(string token);

        /// <summary>
        /// Révoque un refresh token.
        /// </summary>
        /// <param name="token">Token à révoquer</param>
        /// <param name="reason">Raison de la révocation</param>
        /// <param name="revokedByIp">Adresse IP de révocation</param>
        /// <returns>True si révoqué avec succès</returns>
        Task<bool> RevokeRefreshTokenAsync(string token, string reason, string? revokedByIp = null);

        /// <summary>
        /// Révoque tous les refresh tokens d'un utilisateur.
        /// </summary>
        /// <param name="userId">ID de l'utilisateur</param>
        /// <param name="reason">Raison de la révocation</param>
        /// <param name="revokedByIp">Adresse IP de révocation</param>
        /// <returns>Nombre de tokens révoqués</returns>
        Task<int> RevokeAllUserTokensAsync(Guid userId, string reason, string? revokedByIp = null);

        /// <summary>
        /// Nettoie les tokens expirés et révoqués.
        /// </summary>
        /// <returns>Nombre de tokens supprimés</returns>
        Task<int> CleanupExpiredTokensAsync();

        /// <summary>
        /// Obtient un refresh token actif par sa valeur.
        /// </summary>
        /// <param name="token">Valeur du token</param>
        /// <returns>RefreshToken si trouvé et actif</returns>
        Task<RefreshToken?> GetActiveRefreshTokenAsync(string token);

        /// <summary>
        /// Compte le nombre de tokens actifs pour un utilisateur.
        /// </summary>
        /// <param name="userId">ID de l'utilisateur</param>
        /// <returns>Nombre de tokens actifs</returns>
        Task<int> CountActiveTokensAsync(Guid userId);

        /// <summary>
        /// Génère une clé secrète pour l'authentification à deux facteurs.
        /// </summary>
        /// <returns>Clé secrète base32</returns>
        string GenerateTwoFactorSecret();

        /// <summary>
        /// Génère un QR code pour configurer l'authentification 2FA.
        /// </summary>
        /// <param name="email">Email de l'utilisateur</param>
        /// <param name="secret">Clé secrète 2FA</param>
        /// <param name="issuer">Nom de l'application</param>
        /// <returns>URL du QR code</returns>
        string GenerateTwoFactorQrCode(string email, string secret, string issuer = "ECommerce Auth");

        /// <summary>
        /// Valide un code d'authentification à deux facteurs.
        /// </summary>
        /// <param name="secret">Clé secrète de l'utilisateur</param>
        /// <param name="code">Code à valider</param>
        /// <returns>True si le code est valide</returns>
        bool ValidateTwoFactorCode(string secret, string code);
    }
}