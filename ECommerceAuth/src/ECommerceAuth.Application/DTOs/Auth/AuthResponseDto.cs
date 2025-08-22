using System;
using System.Collections.Generic;

namespace ECommerceAuth.Application.DTOs.Auth
{
    /// <summary>
    /// DTO pour les réponses d'authentification (login, refresh token).
    /// </summary>
    /// <remarks>
    /// Ce DTO contient toutes les informations retournées après une authentification réussie :
    /// - Tokens JWT et refresh token
    /// - Informations utilisateur de base
    /// - Rôles et permissions
    /// - Métadonnées de sécurité
    /// 
    /// Les tokens sont retournés de manière sécurisée pour être stockés côté client.
    /// </remarks>
    public class AuthResponseDto
    {
        /// <summary>
        /// Token JWT d'accès (courte durée de vie, généralement 15-30 minutes).
        /// </summary>
        public string AccessToken { get; set; } = string.Empty;

        /// <summary>
        /// Token de rafraîchissement (longue durée de vie, généralement 7-30 jours).
        /// </summary>
        public string RefreshToken { get; set; } = string.Empty;

        /// <summary>
        /// Type de token (toujours "Bearer" pour JWT).
        /// </summary>
        public string TokenType { get; set; } = "Bearer";

        /// <summary>
        /// Durée de vie du token d'accès en secondes.
        /// </summary>
        public int ExpiresIn { get; set; }

        /// <summary>
        /// Informations de base sur l'utilisateur.
        /// </summary>
        public UserInfoDto User { get; set; } = new();

        /// <summary>
        /// Liste des rôles de l'utilisateur.
        /// </summary>
        public List<string> Roles { get; set; } = new();

        /// <summary>
        /// Indique si l'authentification à deux facteurs est requise.
        /// </summary>
        public bool RequiresTwoFactor { get; set; }

        /// <summary>
        /// Date d'expiration du token d'accès.
        /// </summary>
        public DateTime AccessTokenExpiry { get; set; }

        /// <summary>
        /// Date d'expiration du token de rafraîchissement.
        /// </summary>
        public DateTime RefreshTokenExpiry { get; set; }
    }

    /// <summary>
    /// Informations de base sur l'utilisateur incluses dans la réponse d'auth.
    /// </summary>
    public class UserInfoDto
    {
        /// <summary>
        /// Identifiant unique de l'utilisateur.
        /// </summary>
        public Guid Id { get; set; }

        /// <summary>
        /// Nom d'utilisateur.
        /// </summary>
        public string UserName { get; set; } = string.Empty;

        /// <summary>
        /// Adresse email.
        /// </summary>
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// Prénom.
        /// </summary>
        public string? FirstName { get; set; }

        /// <summary>
        /// Nom de famille.
        /// </summary>
        public string? LastName { get; set; }

        /// <summary>
        /// URL de l'avatar.
        /// </summary>
        public string? AvatarUrl { get; set; }

        /// <summary>
        /// Indique si l'email est confirmé.
        /// </summary>
        public bool EmailConfirmed { get; set; }

        /// <summary>
        /// Indique si le 2FA est activé.
        /// </summary>
        public bool TwoFactorEnabled { get; set; }

        /// <summary>
        /// Date de dernière connexion.
        /// </summary>
        public DateTime? LastLoginAt { get; set; }
    }
}