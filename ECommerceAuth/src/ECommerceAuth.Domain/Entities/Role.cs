using System.Collections.Generic;
using ECommerceAuth.Domain.Enums;

namespace ECommerceAuth.Domain.Entities
{
    /// <summary>
    /// Entité représentant un rôle dans le système d'autorisation.
    /// </summary>
    /// <remarks>
    /// Cette entité permet une gestion flexible des rôles :
    /// - Nom du rôle (Buyer, Seller, Admin)
    /// - Description pour clarifier les permissions
    /// - Relation many-to-many avec les utilisateurs
    /// 
    /// Avantages de cette approche :
    /// - Extensibilité : facile d'ajouter de nouveaux rôles
    /// - Flexibilité : un utilisateur peut avoir plusieurs rôles
    /// - Maintenabilité : centralisation de la logique des rôles
    /// </remarks>
    public class Role : BaseEntity
    {
        /// <summary>
        /// Nom du rôle (enum converti en string pour la base de données).
        /// </summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// Description du rôle et de ses permissions.
        /// </summary>
        public string Description { get; set; } = string.Empty;

        /// <summary>
        /// Collection des relations utilisateur-rôle.
        /// </summary>
        public virtual ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();

        /// <summary>
        /// Constructeur par défaut.
        /// </summary>
        public Role() : base()
        {
        }

        /// <summary>
        /// Constructeur avec paramètres pour faciliter la création.
        /// </summary>
        /// <param name="role">Le rôle à partir de l'énumération</param>
        /// <param name="description">Description du rôle</param>
        public Role(UserRole role, string description) : base()
        {
            Name = role.ToString();
            Description = description;
        }
    }
}