using System;

namespace ECommerceAuth.Domain.Entities
{
    /// <summary>
    /// Entité de liaison pour la relation many-to-many entre User et Role.
    /// </summary>
    /// <remarks>
    /// Cette entité permet :
    /// - Une relation many-to-many entre utilisateurs et rôles
    /// - L'ajout de propriétés spécifiques à la relation (date d'attribution, etc.)
    /// - Un contrôle fin des permissions par utilisateur
    /// 
    /// Exemple d'usage :
    /// - Un utilisateur peut être à la fois Buyer et Seller
    /// - Traçabilité de quand un rôle a été attribué
    /// - Possibilité d'ajouter des métadonnées sur l'attribution du rôle
    /// </remarks>
    public class UserRole : BaseEntity
    {
        /// <summary>
        /// Identifiant de l'utilisateur.
        /// </summary>
        public Guid UserId { get; set; }

        /// <summary>
        /// Identifiant du rôle.
        /// </summary>
        public Guid RoleId { get; set; }

        /// <summary>
        /// Date à laquelle le rôle a été attribué à l'utilisateur.
        /// </summary>
        public DateTime AssignedAt { get; set; }

        /// <summary>
        /// Identifiant de l'utilisateur qui a attribué ce rôle (généralement un admin).
        /// Null si attribution automatique lors de l'inscription.
        /// </summary>
        public Guid? AssignedByUserId { get; set; }

        /// <summary>
        /// Navigation property vers l'utilisateur.
        /// </summary>
        public virtual User User { get; set; } = null!;

        /// <summary>
        /// Navigation property vers le rôle.
        /// </summary>
        public virtual Role Role { get; set; } = null!;

        /// <summary>
        /// Navigation property vers l'utilisateur qui a attribué ce rôle.
        /// </summary>
        public virtual User? AssignedByUser { get; set; }

        /// <summary>
        /// Constructeur par défaut.
        /// </summary>
        public UserRole() : base()
        {
            AssignedAt = DateTime.UtcNow;
        }

        /// <summary>
        /// Constructeur avec paramètres.
        /// </summary>
        /// <param name="userId">ID de l'utilisateur</param>
        /// <param name="roleId">ID du rôle</param>
        /// <param name="assignedByUserId">ID de l'utilisateur qui attribue le rôle</param>
        public UserRole(Guid userId, Guid roleId, Guid? assignedByUserId = null) : base()
        {
            UserId = userId;
            RoleId = roleId;
            AssignedByUserId = assignedByUserId;
            AssignedAt = DateTime.UtcNow;
        }
    }
}