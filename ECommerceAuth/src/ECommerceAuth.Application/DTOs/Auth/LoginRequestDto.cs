using System.ComponentModel.DataAnnotations;

namespace ECommerceAuth.Application.DTOs.Auth
{
    /// <summary>
    /// DTO pour les demandes de connexion utilisateur.
    /// </summary>
    /// <remarks>
    /// Ce DTO contient les informations minimales nécessaires pour l'authentification :
    /// - Email comme identifiant unique
    /// - Mot de passe
    /// - Option "Se souvenir de moi" pour les tokens longue durée
    /// - Support optionnel du code 2FA
    /// </remarks>
    public class LoginRequestDto
    {
        /// <summary>
        /// Adresse email de l'utilisateur.
        /// </summary>
        [Required(ErrorMessage = "L'email est requis")]
        [EmailAddress(ErrorMessage = "Format d'email invalide")]
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// Mot de passe de l'utilisateur.
        /// </summary>
        [Required(ErrorMessage = "Le mot de passe est requis")]
        public string Password { get; set; } = string.Empty;

        /// <summary>
        /// Indique si l'utilisateur souhaite rester connecté plus longtemps.
        /// Influence la durée de vie du refresh token.
        /// </summary>
        public bool RememberMe { get; set; } = false;

        /// <summary>
        /// Code d'authentification à deux facteurs (si activé).
        /// </summary>
        [StringLength(6, MinimumLength = 6, ErrorMessage = "Le code 2FA doit contenir exactement 6 chiffres")]
        [RegularExpression(@"^\d{6}$", ErrorMessage = "Le code 2FA doit contenir uniquement des chiffres")]
        public string? TwoFactorCode { get; set; }
    }
}