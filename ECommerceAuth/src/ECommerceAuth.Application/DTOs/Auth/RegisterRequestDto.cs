using System.ComponentModel.DataAnnotations;
using ECommerceAuth.Domain.Enums;

namespace ECommerceAuth.Application.DTOs.Auth
{
    /// <summary>
    /// DTO pour les demandes d'inscription d'utilisateur.
    /// </summary>
    /// <remarks>
    /// Ce DTO contient toutes les informations nécessaires pour créer un nouveau compte :
    /// - Informations de base (nom, email, mot de passe)
    /// - Choix du rôle initial
    /// - Validation des données d'entrée
    /// 
    /// Les annotations de validation permettent une validation côté serveur robuste.
    /// </remarks>
    public class RegisterRequestDto
    {
        /// <summary>
        /// Nom d'utilisateur unique (3-50 caractères).
        /// </summary>
        [Required(ErrorMessage = "Le nom d'utilisateur est requis")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "Le nom d'utilisateur doit contenir entre 3 et 50 caractères")]
        [RegularExpression(@"^[a-zA-Z0-9_]+$", ErrorMessage = "Le nom d'utilisateur ne peut contenir que des lettres, chiffres et underscores")]
        public string UserName { get; set; } = string.Empty;

        /// <summary>
        /// Adresse email valide et unique.
        /// </summary>
        [Required(ErrorMessage = "L'email est requis")]
        [EmailAddress(ErrorMessage = "Format d'email invalide")]
        [StringLength(255, ErrorMessage = "L'email ne peut pas dépasser 255 caractères")]
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// Mot de passe (minimum 8 caractères, avec complexité).
        /// </summary>
        [Required(ErrorMessage = "Le mot de passe est requis")]
        [StringLength(100, MinimumLength = 8, ErrorMessage = "Le mot de passe doit contenir au moins 8 caractères")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]", 
            ErrorMessage = "Le mot de passe doit contenir au moins une minuscule, une majuscule, un chiffre et un caractère spécial")]
        public string Password { get; set; } = string.Empty;

        /// <summary>
        /// Confirmation du mot de passe.
        /// </summary>
        [Required(ErrorMessage = "La confirmation du mot de passe est requise")]
        [Compare("Password", ErrorMessage = "Les mots de passe ne correspondent pas")]
        public string ConfirmPassword { get; set; } = string.Empty;

        /// <summary>
        /// Prénom (optionnel).
        /// </summary>
        [StringLength(50, ErrorMessage = "Le prénom ne peut pas dépasser 50 caractères")]
        public string? FirstName { get; set; }

        /// <summary>
        /// Nom de famille (optionnel).
        /// </summary>
        [StringLength(50, ErrorMessage = "Le nom de famille ne peut pas dépasser 50 caractères")]
        public string? LastName { get; set; }

        /// <summary>
        /// Numéro de téléphone (optionnel).
        /// </summary>
        [Phone(ErrorMessage = "Format de téléphone invalide")]
        public string? PhoneNumber { get; set; }

        /// <summary>
        /// Rôle demandé lors de l'inscription.
        /// Par défaut : Buyer.
        /// </summary>
        public UserRole Role { get; set; } = UserRole.Buyer;

        /// <summary>
        /// Acceptation des conditions d'utilisation.
        /// </summary>
        [Range(typeof(bool), "true", "true", ErrorMessage = "Vous devez accepter les conditions d'utilisation")]
        public bool AcceptTerms { get; set; }
    }
}