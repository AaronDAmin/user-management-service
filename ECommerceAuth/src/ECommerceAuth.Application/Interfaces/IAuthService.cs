using System;
using System.Threading.Tasks;
using ECommerceAuth.Application.DTOs.Auth;
using ECommerceAuth.Domain.Entities;
using System.Collections.Generic;
using System.Linq;

namespace ECommerceAuth.Application.Interfaces
{
    /// <summary>
    /// Interface du service d'authentification.
    /// </summary>
    /// <remarks>
    /// Cette interface définit tous les contrats pour l'authentification :
    /// - Inscription et confirmation d'email
    /// - Connexion avec support 2FA
    /// - Gestion des tokens JWT et refresh tokens
    /// - Réinitialisation de mot de passe
    /// - Gestion de la sécurité (lockout, audit)
    /// 
    /// L'utilisation d'interfaces permet :
    /// - L'injection de dépendance
    /// - Les tests unitaires avec mocking
    /// - La séparation des responsabilités
    /// - L'extensibilité future
    /// </remarks>
    public interface IAuthService
    {
        /// <summary>
        /// Inscrit un nouvel utilisateur dans le système.
        /// </summary>
        /// <param name="request">Données d'inscription</param>
        /// <param name="ipAddress">Adresse IP de l'utilisateur</param>
        /// <param name="userAgent">User Agent du navigateur</param>
        /// <returns>Résultat de l'inscription avec token de confirmation</returns>
        Task<AuthResult> RegisterAsync(RegisterRequestDto request, string ipAddress, string? userAgent = null);

        /// <summary>
        /// Authentifie un utilisateur et génère les tokens.
        /// </summary>
        /// <param name="request">Données de connexion</param>
        /// <param name="ipAddress">Adresse IP de l'utilisateur</param>
        /// <param name="userAgent">User Agent du navigateur</param>
        /// <returns>Résultat de l'authentification avec tokens</returns>
        Task<AuthResult> LoginAsync(LoginRequestDto request, string ipAddress, string? userAgent = null);

        /// <summary>
        /// Rafraîchit un token d'accès expiré.
        /// </summary>
        /// <param name="refreshToken">Token de rafraîchissement</param>
        /// <param name="ipAddress">Adresse IP de l'utilisateur</param>
        /// <param name="userAgent">User Agent du navigateur</param>
        /// <returns>Nouveaux tokens d'accès et de rafraîchissement</returns>
        Task<AuthResult> RefreshTokenAsync(string refreshToken, string ipAddress, string? userAgent = null);

        /// <summary>
        /// Déconnecte un utilisateur et révoque ses tokens.
        /// </summary>
        /// <param name="refreshToken">Token de rafraîchissement à révoquer</param>
        /// <param name="ipAddress">Adresse IP de l'utilisateur</param>
        /// <returns>Résultat de la déconnexion</returns>
        Task<AuthResult> LogoutAsync(string refreshToken, string ipAddress);

        /// <summary>
        /// Confirme l'adresse email d'un utilisateur.
        /// </summary>
        /// <param name="userId">ID de l'utilisateur</param>
        /// <param name="token">Token de confirmation d'email</param>
        /// <returns>Résultat de la confirmation</returns>
        Task<AuthResult> ConfirmEmailAsync(Guid userId, string token);

        /// <summary>
        /// Envoie un email de réinitialisation de mot de passe.
        /// </summary>
        /// <param name="email">Adresse email de l'utilisateur</param>
        /// <returns>Résultat de l'envoi</returns>
        Task<AuthResult> ForgotPasswordAsync(string email);

        /// <summary>
        /// Réinitialise le mot de passe d'un utilisateur.
        /// </summary>
        /// <param name="email">Adresse email de l'utilisateur</param>
        /// <param name="token">Token de réinitialisation</param>
        /// <param name="newPassword">Nouveau mot de passe</param>
        /// <returns>Résultat de la réinitialisation</returns>
        Task<AuthResult> ResetPasswordAsync(string email, string token, string newPassword);

        /// <summary>
        /// Active l'authentification à deux facteurs pour un utilisateur.
        /// </summary>
        /// <param name="userId">ID de l'utilisateur</param>
        /// <returns>Clé secrète pour configurer l'authenticator</returns>
        Task<AuthResult> EnableTwoFactorAsync(Guid userId);

        /// <summary>
        /// Désactive l'authentification à deux facteurs.
        /// </summary>
        /// <param name="userId">ID de l'utilisateur</param>
        /// <param name="code">Code de vérification 2FA</param>
        /// <returns>Résultat de la désactivation</returns>
        Task<AuthResult> DisableTwoFactorAsync(Guid userId, string code);

        /// <summary>
        /// Vérifie si un utilisateur existe par email.
        /// </summary>
        /// <param name="email">Adresse email à vérifier</param>
        /// <returns>True si l'utilisateur existe</returns>
        Task<bool> UserExistsAsync(string email);

        /// <summary>
        /// Révoque tous les tokens de rafraîchissement d'un utilisateur.
        /// </summary>
        /// <param name="userId">ID de l'utilisateur</param>
        /// <param name="reason">Raison de la révocation</param>
        /// <returns>Résultat de la révocation</returns>
        Task<AuthResult> RevokeAllTokensAsync(Guid userId, string reason);
    }

    /// <summary>
    /// Résultat d'une opération d'authentification.
    /// </summary>
    public class AuthResult
    {
        /// <summary>
        /// Indique si l'opération a réussi.
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Message descriptif du résultat.
        /// </summary>
        public string Message { get; set; } = string.Empty;

        /// <summary>
        /// Données de réponse (tokens, utilisateur, etc.).
        /// </summary>
        public AuthResponseDto? Data { get; set; }

        /// <summary>
        /// Liste des erreurs en cas d'échec.
        /// </summary>
        public List<string> Errors { get; set; } = new();

        /// <summary>
        /// Indique si une authentification à deux facteurs est requise.
        /// </summary>
        public bool RequiresTwoFactor { get; set; }

        /// <summary>
        /// Données supplémentaires (clé 2FA, etc.).
        /// </summary>
        public Dictionary<string, object> AdditionalData { get; set; } = new();

        /// <summary>
        /// Crée un résultat de succès.
        /// </summary>
        public static AuthResult SuccessResult(string message, AuthResponseDto? data = null)
        {
            return new AuthResult
            {
                Success = true,
                Message = message,
                Data = data
            };
        }

        /// <summary>
        /// Crée un résultat d'échec.
        /// </summary>
        public static AuthResult FailureResult(string message, params string[] errors)
        {
            return new AuthResult
            {
                Success = false,
                Message = message,
                Errors = errors.ToList()
            };
        }

        /// <summary>
        /// Crée un résultat nécessitant une authentification 2FA.
        /// </summary>
        public static AuthResult TwoFactorRequiredResult(string message)
        {
            return new AuthResult
            {
                Success = false,
                Message = message,
                RequiresTwoFactor = true
            };
        }
    }
}